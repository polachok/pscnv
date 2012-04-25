/*
 * Copyright 2009 Red Hat Inc.
 * Copyright (c) 2006 Dave Airlie <airlied@linux.ie>
 * Copyright © 2006-2008,2010 Intel Corporation
 *   Jesse Barnes <jesse.barnes@intel.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *	Eric Anholt <eric@anholt.net>
 *	Chris Wilson <chris@chris-wilson.co.uk>
 *
 * Copyright (c) 2011 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Konstantin Belousov under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "nouveau_drv.h"
#include "nouveau_reg.h"
#include "nouveau_i2c.h"
#include "nouveau_hw.h"

#define T_TIMEOUT  2200000
#define T_RISEFALL 1000
#define T_HOLD     5000

static void
i2c_drive_scl(void *data, int state)
{
	struct nouveau_i2c_chan *port = data;
	if (port->type == 0) {
		u8 val = NVReadVgaCrtc(port->dev, 0, port->wr);
		if (state) val |= 0x20;
		else	   val &= 0xdf;
		NVWriteVgaCrtc(port->dev, 0, port->wr, val | 0x01);
	} else
	if (port->type == 4) {
		nv_mask(port->dev, port->wr, 0x2f, state ? 0x21 : 0x01);
	} else
	if (port->type == 5) {
		if (state) port->state |= 0x01;
		else	   port->state &= 0xfe;
		nv_wr32(port->dev, port->wr, 4 | port->state);
	}
}

static void
i2c_drive_sda(void *data, int state)
{
	struct nouveau_i2c_chan *port = data;
	if (port->type == 0) {
		u8 val = NVReadVgaCrtc(port->dev, 0, port->wr);
		if (state) val |= 0x10;
		else	   val &= 0xef;
		NVWriteVgaCrtc(port->dev, 0, port->wr, val | 0x01);
	} else
	if (port->type == 4) {
		nv_mask(port->dev, port->wr, 0x1f, state ? 0x11 : 0x01);
	} else
	if (port->type == 5) {
		if (state) port->state |= 0x02;
		else	   port->state &= 0xfd;
		nv_wr32(port->dev, port->wr, 4 | port->state);
	}
}

static int
i2c_sense_scl(void *data)
{
	struct nouveau_i2c_chan *port = data;
	struct drm_nouveau_private *dev_priv = port->dev->dev_private;
	if (port->type == 0) {
		return !!(NVReadVgaCrtc(port->dev, 0, port->rd) & 0x04);
	} else
	if (port->type == 4) {
		return !!(nv_rd32(port->dev, port->rd) & 0x00040000);
	} else
	if (port->type == 5) {
		if (dev_priv->card_type < NV_D0)
			return !!(nv_rd32(port->dev, port->rd) & 0x01);
		else
			return !!(nv_rd32(port->dev, port->rd) & 0x10);
	}
	return 0;
}

static int
i2c_sense_sda(void *data)
{
	struct nouveau_i2c_chan *port = data;
	struct drm_nouveau_private *dev_priv = port->dev->dev_private;
	if (port->type == 0) {
		return !!(NVReadVgaCrtc(port->dev, 0, port->rd) & 0x08);
	} else
	if (port->type == 4) {
		return !!(nv_rd32(port->dev, port->rd) & 0x00080000);
	} else
	if (port->type == 5) {
		if (dev_priv->card_type < NV_D0)
			return !!(nv_rd32(port->dev, port->rd) & 0x02);
		else
			return !!(nv_rd32(port->dev, port->rd) & 0x20);
	}
	return 0;
}

static void
i2c_delay(struct nouveau_i2c_chan *port, u32 nsec)
{
	udelay((nsec + 500) / 1000);
}

static bool
i2c_raise_scl(struct nouveau_i2c_chan *port)
{
	u32 timeout = T_TIMEOUT / T_RISEFALL;

	i2c_drive_scl(port, 1);
	do {
		i2c_delay(port, T_RISEFALL);
	} while (!i2c_sense_scl(port) && --timeout);

	return timeout != 0;
}

static int
i2c_start(struct nouveau_i2c_chan *port)
{
	int ret = 0;

	port->state  = i2c_sense_scl(port);
	port->state |= i2c_sense_sda(port) << 1;
	if (port->state != 3) {
		i2c_drive_scl(port, 0);
		i2c_drive_sda(port, 1);
		if (!i2c_raise_scl(port))
			ret = -EBUSY;
	}

	i2c_drive_sda(port, 0);
	i2c_delay(port, T_HOLD);
	i2c_drive_scl(port, 0);
	i2c_delay(port, T_HOLD);
	return ret;
}

static void
i2c_stop(struct nouveau_i2c_chan *port)
{
	i2c_drive_scl(port, 0);
	i2c_drive_sda(port, 0);
	i2c_delay(port, T_RISEFALL);

	i2c_drive_scl(port, 1);
	i2c_delay(port, T_HOLD);
	i2c_drive_sda(port, 1);
	i2c_delay(port, T_HOLD);
}

static int
i2c_bitw(struct nouveau_i2c_chan *port, int sda)
{
	i2c_drive_sda(port, sda);
	i2c_delay(port, T_RISEFALL);

	if (!i2c_raise_scl(port))
		return -ETIMEDOUT;
	i2c_delay(port, T_HOLD);

	i2c_drive_scl(port, 0);
	i2c_delay(port, T_HOLD);
	return 0;
}

static int
i2c_bitr(struct nouveau_i2c_chan *port)
{
	int sda;

	i2c_drive_sda(port, 1);
	i2c_delay(port, T_RISEFALL);

	if (!i2c_raise_scl(port))
		return -ETIMEDOUT;
	i2c_delay(port, T_HOLD);

	sda = i2c_sense_sda(port);

	i2c_drive_scl(port, 0);
	i2c_delay(port, T_HOLD);
	return sda;
}

static int
i2c_get_byte(struct nouveau_i2c_chan *port, u8 *byte, bool last)
{
	int i, bit;

	*byte = 0;
	for (i = 7; i >= 0; i--) {
		bit = i2c_bitr(port);
		if (bit < 0)
			return bit;
		*byte |= bit << i;
	}

	return i2c_bitw(port, last ? 1 : 0);
}

static int
i2c_put_byte(struct nouveau_i2c_chan *port, u8 byte)
{
	int i, ret;
	for (i = 7; i >= 0; i--) {
		ret = i2c_bitw(port, !!(byte & (1 << i)));
		if (ret < 0)
			return ret;
	}

	ret = i2c_bitr(port);
	if (ret == 1) /* nack */
		ret = -EIO;
	return ret;
}

static int
i2c_addr(struct nouveau_i2c_chan *port, struct i2c_msg *msg)
{
	u32 addr = msg->slave << 1;
	if (msg->flags & I2C_M_RD)
		addr |= 1;
	return i2c_put_byte(port, addr);
}

static int
i2c_bit_xfer(struct nouveau_i2c_chan *port, struct i2c_msg *msgs, int num)
{
	struct i2c_msg *msg = msgs;
	int ret = 0, mcnt = num;

	while (!ret && mcnt--) {
		u8 remaining = msg->len;
		u8 *ptr = msg->buf;

		ret = i2c_start(port);
		if (ret == 0)
			ret = i2c_addr(port, msg);

		if (msg->flags & I2C_M_RD) {
			while (!ret && remaining--)
				ret = i2c_get_byte(port, ptr++, !remaining);
		} else {
			while (!ret && remaining--)
				ret = i2c_put_byte(port, *(ptr++));
		}

		msg++;
	}
	if (ret < 0)
		NV_WARN(port->dev, "i2c xfer %s on %u / %02x returns: %d\n", 
			(msg->flags & I2C_M_RD) ? "read" : "write",
			device_get_unit(port->adapter), msg->slave, ret);

	i2c_stop(port);
	return ret < 0 ? -ret : 0;
}

static const uint32_t nv50_i2c_port[] = {
	0x00e138, 0x00e150, 0x00e168, 0x00e180,
	0x00e254, 0x00e274, 0x00e764, 0x00e780,
	0x00e79c, 0x00e7b8
};
#define NV50_I2C_PORTS DRM_ARRAY_SIZE(nv50_i2c_port)

int
nouveau_i2c_init(struct drm_device *dev, struct dcb_i2c_entry *entry, int index)
{
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	struct nouveau_i2c_chan *i2c;
	int ret;
	device_t idev;

	if (entry->chan)
		return -EEXIST;

	idev = device_add_child(dev->device, "pscnv_iic", index);
	if (!idev) {
		return -ENODEV;
	}
	ret = device_probe_and_attach(idev);
	if (ret) {
		NV_ERROR(dev, "Couldn't attach device: %d\n", ret);
		device_delete_child(dev->device, idev);
		return -ret;
	}
	device_quiet(idev);
	i2c = device_get_softc(idev);
	ret = -ENODEV;
	if (!i2c)
		goto err;

	ret = -EINVAL;
	switch (entry->port_type) {
	case 0:
		i2c->rd = entry->read;
		i2c->wr = entry->write;
		break;
	case 4:
		i2c->wr = i2c->rd = 0x600800 + entry->read;
		break;
	case 5:
		if (dev_priv->card_type < NV_D0) {
			uint32_t idx = entry->read & 0xf;
			if (idx >= NV50_I2C_PORTS) {
				NV_ERROR(dev, "unknown i2c port %d\n",
					 entry->read);
				goto err;
			}
			i2c->rd = nv50_i2c_port[idx];
		} else
			i2c->rd = 0x00d014 + (entry->read & 0xf) * 0x20;
		i2c->wr = i2c->rd;
		break;
	case 6:
		i2c->rd = i2c->wr = entry->read;
		break;
	default:
		NV_ERROR(dev, "DCB I2C port type %d unknown\n",
			 entry->port_type);
		goto err;
	}

	i2c->adapter = idev;
	i2c->type = entry->port_type;
	entry->chan = i2c;
	return 0;

err:
	device_delete_child(dev->device, idev);
	return ret;
}

void
nouveau_i2c_fini(struct drm_device *dev, struct dcb_i2c_entry *entry)
{
	if (!entry->chan)
		return;

	device_delete_child(dev->device, entry->chan->adapter);
}

struct nouveau_i2c_chan *
nouveau_i2c_find(struct drm_device *dev, int index)
{
	struct drm_nouveau_private *dev_priv = dev->dev_private;
	struct dcb_i2c_entry *i2c = &dev_priv->vbios.dcb.i2c[index];

	if (index >= DCB_MAX_NUM_I2C_ENTRIES)
		return NULL;

	if (dev_priv->chipset >= NV_50 && (i2c->entry & 0x00000100)) {
		uint32_t reg = 0xe500, val;

		if (i2c->port_type == 6) {
			reg += i2c->read * 0x50;
			val  = 0x2002;
		} else {
			reg += ((i2c->entry & 0x1e00) >> 9) * 0x50;
			val  = 0xe001;
		}

		/* nfi, but neither auxch or i2c work if it's 1 */
		nv_mask(dev, reg + 0x0c, 0x00000001, 0x00000000);
		/* nfi, but switches auxch vs normal i2c */
		nv_mask(dev, reg + 0x00, 0x0000f003, val);
	}

	if (!i2c->chan && nouveau_i2c_init(dev, i2c, index))
		return NULL;
	return i2c->chan;
}

bool
nouveau_probe_i2c_addr(struct nouveau_i2c_chan *i2c, int addr)
{
	uint8_t buf[] = { 0 };
	struct i2c_msg msgs[] = {
		{
			.slave = addr,
			.flags = 0,
			.len = 1,
			.buf = buf,
		},
		{
			.slave = addr,
			.flags = IIC_M_RD,
			.len = 1,
			.buf = buf,
		}
	};

	return !iicbus_transfer(i2c->bus, msgs, 2);
}

int
nouveau_i2c_identify(struct drm_device *dev, const char *what,
		     struct i2c_board_info *info,
		     bool (*match)(struct nouveau_i2c_chan *,
				   struct i2c_board_info *),
		     int index)
{
	struct nouveau_i2c_chan *i2c = nouveau_i2c_find(dev, index);
	int i;

	NV_DEBUG(dev, "Probing %ss on I2C bus: %d\n", what, index);

	for (i = 0; info[i].addr; i++) {
		if (nouveau_probe_i2c_addr(i2c, info[i].addr) &&
		    (!match || match(i2c, &info[i]))) {
			NV_INFO(dev, "Detected %s on %i\n", what, index);
			return i;
		}
	}

	NV_DEBUG(dev, "No devices found.\n");
	return -ENODEV;
}

static int
pscnv_iic_attach(device_t idev)
{
	struct drm_nouveau_private *dev_priv;
	struct nouveau_i2c_chan *sc;
	int pin;

	sc = device_get_softc(idev);
	sc->dev = device_get_softc(device_get_parent(idev));
	dev_priv = sc->dev->dev_private;
	pin = device_get_unit(idev);

	snprintf(sc->name, sizeof(sc->name), "pscnv_iic %u", pin);
	device_set_desc(idev, sc->name);

	/* add bus interface device */
	sc->bus = sc->iic_dev = device_add_child(idev, "iicbus", -1);
	if (sc->iic_dev == NULL) {
		NV_ERROR(sc->dev, "Could not add iicbus to iic!\n");
		return (ENXIO);
	}
	device_quiet(sc->iic_dev);
	bus_generic_attach(idev);

	return (0);
}

static int
pscnv_iic_transfer(device_t idev, struct iic_msg *msgs, uint32_t nmsgs)
{
	struct drm_nouveau_private *dev_priv;
	struct nouveau_i2c_chan *auxch;
	struct i2c_msg *msg = msgs;
	int ret, mcnt = nmsgs;

	auxch = device_get_softc(idev);
	dev_priv = auxch->dev->dev_private;
	if (auxch->type < 6)
		return i2c_bit_xfer(auxch, msgs, nmsgs);

	while (mcnt--) {
		u8 remaining = msg->len;
		u8 *ptr = msg->buf;

		while (remaining) {
			u8 cnt = (remaining > 16) ? 16 : remaining;
			u8 cmd;

			if (msg->flags & I2C_M_RD)
				cmd = AUX_I2C_READ;
			else
				cmd = AUX_I2C_WRITE;

			if (mcnt || remaining > 16)
				cmd |= AUX_I2C_MOT;

			NV_WARN(auxch->dev, "Slave is: %02x\n", msg->slave);
			ret = nouveau_dp_auxch(auxch, cmd, msg->slave, ptr, cnt);
			if (ret < 0)
				return (-ret);

			ptr += cnt;
			remaining -= cnt;
		}

		msg++;
	}

	return (0);
}

static int
pscnv_iic_probe(device_t dev)
{
	return (BUS_PROBE_SPECIFIC);
}

static int
pscnv_iic_detach(device_t idev)
{
	struct nouveau_i2c_chan *sc;
	device_t child;

	sc = device_get_softc(idev);
	child = sc->iic_dev;
	bus_generic_detach(idev);
	if (child)
		device_delete_child(idev, child);
	return (0);
}

static int
pscnv_iicbus_reset(device_t idev, u_char speed, u_char addr, u_char *oldaddr)
{
	return (0);
}

/* DP transfer with auxch */
static device_method_t pscnv_iic_methods[] = {
	DEVMETHOD(device_probe,		pscnv_iic_probe),
	DEVMETHOD(device_attach,	pscnv_iic_attach),
	DEVMETHOD(device_detach,	pscnv_iic_detach),
	DEVMETHOD(iicbus_reset,		pscnv_iicbus_reset),
	DEVMETHOD(iicbus_transfer,	pscnv_iic_transfer),
	DEVMETHOD_END
};
static driver_t pscnv_iic_driver = {
	"pscnv_iic",
	pscnv_iic_methods,
	sizeof(struct nouveau_i2c_chan)
};
static devclass_t pscnv_iic_devclass;
DRIVER_MODULE_ORDERED(pscnv_iic, drm, pscnv_iic_driver,
    pscnv_iic_devclass, 0, 0, SI_ORDER_FIRST);
DRIVER_MODULE(iicbus, pscnv_iic, iicbus_driver, iicbus_devclass, 0, 0);
