/*
 * Copyright (C), 2020-2023 CCX Technologies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/spi/spi.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/version.h>

#include "avionics.h"
#include "avionics-device.h"

MODULE_DESCRIPTION("HOLT Hi-6138 MIL-1553 Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.2");

#define HI6138_REG_MCFG1			0x0000
#define HI6138_REG_MCFG1_TXINHA		(1<<15)
#define HI6138_REG_MCFG1_TXINHB		(1<<14)
#define HI6138_REG_MCFG1_MTENA		(1<<8)
#define HI6138_REG_MCFG1_INTSEL		(1<<2)
#define HI6138_REG_MCFG1_IMTA		(1<<1)

#define HI6138_REG_HIRQ_ENABLE		0x000f
#define HI6138_REG_HIRQ_PENDING		0x0006
#define HI6138_REG_HIRQ_OUTPUT		0x0013

#define HI6138_REG_HIRQ_HSPINT		(1<<15)
#define HI6138_REG_HIRQ_RAMPF		(1<<14)
#define HI6138_REG_HIRQ_RAMIF		(1<<13)
#define HI6138_REG_HIRQ_LBFA		(1<<12)
#define HI6138_REG_HIRQ_LBFB		(1<<11)
#define HI6138_REG_HIRQ_MTTRO		(1<<10)
#define HI6138_REG_HIRQ_BCTTRO		(1<<9)
#define HI6138_REG_HIRQ_RTTM		(1<<7)
#define HI6138_REG_HIRQ_MTTM		(1<<6)
#define HI6138_REG_HIRQ_BCTTM		(1<<5)
#define HI6138_REG_HIRQ_RTAPF		(1<<3)
#define HI6138_REG_HIRQ_RTIP		(1<<2)
#define HI6138_REG_HIRQ_MTIP		(1<<1)
#define HI6138_REG_HIRQ_BCIP		(1<<0)

#define HI6138_REG_SMTIRQ_ENABLE	0x0011
#define HI6138_REG_SMTIRQ_PENDING	0x0008
#define HI6138_REG_SMTIRQ_OUTPUT	0x0015

#define HI6138_REG_SMTIRQ_CBUFRO	(1<<8)
#define HI6138_REG_SMTIRQ_DBUFRO	(1<<7)
#define HI6138_REG_SMTIRQ_CBUFMAT	(1<<6)
#define HI6138_REG_SMTIRQ_DBUFMAT	(1<<5)
#define HI6138_REG_SMTIRQ_SMTMERR	(1<<4)
#define HI6138_REG_SMTIRQ_SMTEOM	(1<<3)

#define HI6138_REG_SMTSTART		0x002F
#define HI6138_REG_SMTNEXT		0x0030
#define HI6138_REG_SMTLAST		0x0031
#define HI6138_REG_SMTCNT		0x003a

#define HI6138_REG_SMTCFG			0x0029
#define HI6138_REG_SMTCFG_MTTO_LONG	(3<<14)
#define HI6138_REG_SMTCFG_MTSRR_ANY	(3<<5)
#define HI6138_REG_SMTCFG_MTCRIW	(1<<4)
#define HI6138_REG_SMTCFG_MTSRR		(3<<5)

#define HI6138_REG_MEMPTRA		0x000b
#define HI6138_REG_MEMPTRB		0x000c
#define HI6138_REG_MEMPTRC		0x000d
#define HI6138_REG_MEMPTRD		0x000e

#define HI6138_REG_MCFG2		0x004e

#define HI6138_REG_TIME_TAG_CFG			0x0039
#define HI6138_REG_TIME_TAG_CFG_MTTCK0	(1<<4)
#define HI6138_REG_TIME_TAG_CFG_MTTCK1	(1<<5)
#define HI6138_REG_TIME_TAG_CFG_MTTCK2	(1<<6)
#define HI6138_REG_TIME_TAG_CFG_MTTCK3	(1<<7)

#define HI6138_OPCODE_ENABLE_MEMPTRA	0xd8
#define HI6138_OPCODE_ENABLE_MEMPTRB	0xd9
#define HI6138_OPCODE_ENABLE_MEMPTRC	0xda
#define HI6138_OPCODE_ENABLE_MEMPTRD	0xdb

#define HI6138_OPCODE_ADD1_MEMPTR	0xd0
#define HI6138_OPCODE_ADD2_MEMPTR	0xd2
#define HI6138_OPCODE_ADD4_MEMPTR	0xd4

#define HI6138_OPCODE_READ_MEMPTR	0x40
#define HI6138_OPCODE_WRITE_MEMPTR	0xc0

#define HI6138_CMD_STACK_START		0x0600
#define HI6138_CMD_STACK_IRQ		0x0adf
#define HI6138_CMD_STACK_END		0x0aff

#define HI6138_DATA_STACK_START		0x0b00
#define HI6138_DATA_STACK_IRQ		0x18ff
#define HI6138_DATA_STACK_END		0x1fff

#define HI6138_RX_DELAY_MIN         2500 /* 2.5ms */
#define HI6138_RX_DELAY_MAX         3000 /* 3ms */

struct hi6138 {
	struct net_device *bm;
	struct workqueue_struct *wq;
	struct work_struct worker;
	int reset_gpio;
	int ackirq_gpio;
	int irq;
	__u32 aclk;
	struct mutex lock;
	atomic_t bm_enabled;
	struct spi_device *spi;
};

struct hi6138_priv {
	struct net_device *dev;
	struct spi_device *spi;
	struct sk_buff_head skbq;
	struct mutex *lock;
	atomic_t *bm_enabled;
	__u16 smt_last_addr;
};

static int hi6138_get_fastaccess(struct spi_device *spi, __u8 address, __u16 *value)
{
	int err;
	__u16 buffer;
	__u8 cmd = ((address&0x0f) << 2);

	err = spi_write_then_read(spi, &cmd, sizeof(cmd),
				  &buffer, sizeof(buffer));
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to fast-access read 0x%x\n",
			   address);
		return err;
	}

	*value = be16_to_cpu(buffer);

	return 0;
}

static int hi6138_set_fastaccess(struct spi_device *spi, __u8 address, __u16 value)
{
	int err;
	__u16 vbuffer;
	__u8 buffer[3];

	buffer[0] = 0x80 | (address&0x3f);
	vbuffer = cpu_to_be16(value);
	memcpy(&buffer[1], &vbuffer, sizeof(vbuffer));

	err = spi_write(spi, buffer, sizeof(buffer));
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to fast-access write 0x%x\n",
			   address);
		return err;
	}

	return 0;
}

static int hi6138_set_mem(struct spi_device *spi, __u16 address, __u16 *value,
			  int length)
{
	int err, i;
	__u16 vbuffer;
	__u8 *buffer;

	err = hi6138_set_fastaccess(spi, HI6138_REG_MEMPTRA, address);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to set memory pointer to 0x%x\n",
			   address);
		return err;
	}

	buffer = kmalloc(1 + sizeof(vbuffer)*length, GFP_KERNEL);
	if (buffer == NULL) {
		pr_err("avionics-hi6138: Failed to allocate memory\n");
		return -ENOMEM;
	}

	buffer[0] = HI6138_OPCODE_WRITE_MEMPTR;
	for(i = 0; i < length; i++) {
		vbuffer = cpu_to_be16(value[i]);
		memcpy(&buffer[1+i*sizeof(vbuffer)], &vbuffer, sizeof(vbuffer));
	}

	err = spi_write(spi, buffer, 1 + sizeof(vbuffer)*length);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to write to memory at 0x%x\n",
			   address);
		 kvfree(buffer);
		return err;
	}

	kvfree(buffer);
	return 0;
}

static int hi6138_get_mem(struct spi_device *spi, __u16 address, __u16 *value,
			  int length)
{
	int err, i;
	__u16 vbuffer;
	__u8 *buffer;
	__u8 cmd = HI6138_OPCODE_READ_MEMPTR;

	err = hi6138_set_fastaccess(spi, HI6138_REG_MEMPTRA, address);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to set memory pointer to 0x%x\n",
			   address);
		return err;
	}

	buffer = kmalloc(sizeof(vbuffer)*length, GFP_KERNEL);
	if (buffer == NULL) {
		pr_err("avionics-hi6138: Failed to allocate memory\n");
		return -ENOMEM;
	}

	err = spi_write_then_read(spi, &cmd, sizeof(cmd),
				  buffer, sizeof(vbuffer)*length);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to read from memory at 0x%x\n",
			   address);
		kvfree(buffer);
		return err;
	}

	for(i = 0; i < length; i++) {
		memcpy(&vbuffer, &buffer[i*sizeof(vbuffer)], sizeof(vbuffer));
		value[i] = be16_to_cpu(vbuffer);
	}

	kvfree(buffer);
	return 0;
}

static int hi6138_get_mem_bytes(struct spi_device *spi, __u16 address, __u8 *value,
			  int length)
{
	int err;
	__u8 cmd = HI6138_OPCODE_READ_MEMPTR;

	err = hi6138_set_fastaccess(spi, HI6138_REG_MEMPTRA, address);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to set memory pointer to 0x%x\n",
			   address);
		return err;
	}

	err = spi_write_then_read(spi, &cmd, sizeof(cmd), value, length);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to read from memory at 0x%x\n",
			   address);
		return err;
	}

	return 0;
}

static int hi6138_get_reg(struct spi_device *spi, __u16 address, __u16 *value)
{
	return hi6138_get_mem(spi, address, value, 1);
}

__attribute__((unused)) static int hi6138_set_reg(struct spi_device *spi, __u16 address, __u16 value)
{
	return hi6138_set_mem(spi, address, &value, 1);
}

static void hi6138_get_mil1553bm(struct avionics_mil1553bm *config,
			   const struct net_device *dev)
{
	struct hi6138_priv *priv;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi6138-bm: Failed to get private data\n");
		return;
	}

	/* TODO: add get settings here */

}

static int hi6138_set_mil1553bm(struct avionics_mil1553bm *config,
				 const struct net_device *dev)
{
	struct hi6138_priv *priv;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi6138-bm: Failed to get private data\n");
		return -ENODEV;
	}

	/* TODO: add set settings here */

	return 0;
}

static struct avionics_ops hi6138_mil553bm_ops = {
	.name = "mil1553bm%d",
	.get_mil1553bm = hi6138_get_mil1553bm,
	.set_mil1553bm = hi6138_set_mil1553bm,
};

static int hi6138_bm_open(struct net_device *dev)
{
	struct hi6138_priv *priv;
	int err;
	__u16 mcfg1;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi6138-bm: Failed to get private data\n");
		return -EINVAL;
	}

	if (atomic_read(priv->bm_enabled)) {
		pr_err("avionics-hi6138-bm: Bus Monitor already running\n");
		return 0;
	}

	err = hi6138_get_fastaccess(priv->spi, HI6138_REG_MCFG1, &mcfg1);
	if (err < 0) {
		pr_err("avionics-hi6138-bm: Failed read master config register 1\n");
		return err;
	}

	err = hi6138_set_fastaccess(priv->spi, HI6138_REG_MCFG1,
					mcfg1|HI6138_REG_MCFG1_MTENA);
	if (err < 0) {
		pr_err("avionics-hi6138-bm: Failed set master config register 1\n");
		return err;
	}

	err = hi6138_set_fastaccess(priv->spi, HI6138_REG_SMTIRQ_ENABLE,
					HI6138_REG_SMTIRQ_SMTEOM);
	if (err < 0) {
		pr_err("avionics-hi6138-bm: Failed set SMT IRQ Enable register\n");
		return err;
	}

	err = hi6138_set_fastaccess(priv->spi, HI6138_REG_SMTIRQ_OUTPUT,
					HI6138_REG_SMTIRQ_SMTEOM);
	if (err < 0) {
		pr_err("avionics-hi6138-bm: Failed set SMT IRQ Output register\n");
		return err;
	}

	err = hi6138_set_fastaccess(priv->spi, HI6138_REG_SMTCFG, 0x0803
					| HI6138_REG_SMTCFG_MTTO_LONG
					| HI6138_REG_SMTCFG_MTCRIW |
					HI6138_REG_SMTCFG_MTSRR);
	if (err < 0) {
		pr_err("avionics-hi6138-bm: Failed set SMT config register\n");
		return err;
	}

	priv->smt_last_addr = 0;

	atomic_set(priv->bm_enabled, 1);

	pr_warn("avionics-hi6138-bm: Receiver Enabled\n");

	return 0;
}

static int hi6138_bm_stop(struct net_device *dev)
{
	struct hi6138_priv *priv;
	int err;
	__u16 mcfg1;

	pr_warn("avionics-hi6138-bm: Disabling Receiver\n");

	netif_stop_queue(dev);

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi6138-bm: Failed to get private data\n");
		return -EINVAL;
	}

	atomic_set(priv->bm_enabled, 0);

	err = hi6138_get_fastaccess(priv->spi, HI6138_REG_MCFG1, &mcfg1);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed read master config register 1\n");
		return err;
	}

	err = hi6138_set_fastaccess(priv->spi, HI6138_REG_MCFG1,
					mcfg1&(~HI6138_REG_MCFG1_MTENA));
	if (err < 0) {
		pr_err("avionics-hi6138: Failed set master config register 1\n");
		return err;
	}

	err = hi6138_set_fastaccess(priv->spi, HI6138_REG_SMTIRQ_ENABLE, 0);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed set SMT IRQ Enable register\n");
		return err;
	}

	err = hi6138_set_fastaccess(priv->spi, HI6138_REG_SMTIRQ_OUTPUT, 0);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed set SMT IRQ Output register\n");
		return err;
	}

	return 0;
}

static int hi6138_irq_bm(struct net_device *dev)
{
	struct hi6138_priv *priv;
	struct net_device_stats *stats;
	__u16 smtirq_status, cmd_addr, data_addr, cmd_wrd, length,
		  response_time, block_status, msg_ts[3], buffer[8], vbuffer;
	int err, wrapped = 0;
	struct sk_buff *skb;
	struct timespec64 tv;
	avionics_data *data;

	stats = &dev->stats;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi6138-bm: Failed to get private data\n");
		return -EINVAL;
	}

	err = hi6138_get_fastaccess(priv->spi, HI6138_REG_SMTIRQ_PENDING,
					&smtirq_status);
	if (err < 0) {
		pr_err("avionics-hi6138-bm: Failed read irq"
			   " pending register\n");
		return err;
	}

	if (smtirq_status & HI6138_REG_SMTIRQ_SMTEOM) {
		err = hi6138_get_reg(priv->spi, HI6138_REG_SMTLAST, &cmd_addr);
		if (err < 0) {
			pr_err("avionics-hi6138-bm: Failed read"
				   " last address register\n");
			return err;
		}

		if ((cmd_addr < HI6138_CMD_STACK_START) ||
				(cmd_addr > HI6138_CMD_STACK_END)) {
			pr_err("avionics-hi6138: cmd_addr is out of range, 0x%x\n", cmd_addr);
			return 0;
		}

		if (priv->smt_last_addr == 0) {
			/* first message after restart */
			priv->smt_last_addr = cmd_addr;
		}

		if(priv->smt_last_addr > cmd_addr) {
			wrapped = 1;
		}

		for(; ((priv->smt_last_addr <= cmd_addr) || wrapped) ;
			priv->smt_last_addr += 8) {
			if(priv->smt_last_addr >= HI6138_CMD_STACK_END) {
				priv->smt_last_addr = HI6138_CMD_STACK_START;
				wrapped = 0;
			}

			err = hi6138_get_mem(priv->spi, priv->smt_last_addr, buffer, 8);
			if (err < 0) {
				pr_err("avionics-hi6138-bm: Failed read message block\n");
				return err;
			}

			cmd_wrd = buffer[7];
			data_addr = buffer[6];
			length = buffer[5];
			response_time = buffer[4];
			block_status = buffer[3];
			msg_ts[2] = buffer[2];
			msg_ts[1] = buffer[1];
			msg_ts[0] = buffer[0];

			if ((data_addr < HI6138_DATA_STACK_START) ||
					(data_addr > HI6138_DATA_STACK_END)) {
				pr_err("avionics-hi6138: data_addr is out of range, 0x%x\n", data_addr);
				return 0;
			}

			data = kzalloc(sizeof(avionics_data) + length, GFP_KERNEL);
			if (data == NULL) {
				pr_err("avionics-hi6138-bm: Failed to allocate data buffer\n");
				return -ENOMEM;
			}
			data->width = sizeof(__u16);
			data->length = length;

			ktime_get_real_ts64(&tv);
			data->time_msecs = (tv.tv_sec*MSEC_PER_SEC) + (tv.tv_nsec/NSEC_PER_MSEC);

			data->status = (response_time << 16) + block_status;
			data->count = (msg_ts[2] << 32) + (msg_ts[1] << 16) + msg_ts[0];

            vbuffer = cpu_to_be16(cmd_wrd);
			memcpy(data->data, &vbuffer, sizeof(vbuffer));

			if (length > 2) {
				err = hi6138_get_mem_bytes(priv->spi, data_addr,
                        &data->data[sizeof(vbuffer)], length-sizeof(vbuffer));
				if (err < 0) {
					pr_err("avionics-hi6138-bm: Failed read data block\n");
					return err;
				}
			}

			skb = avionics_device_alloc_skb(dev, sizeof(avionics_data) + length);
			if (unlikely(!skb)) {
				pr_err("avionics-hi6138-bm: Failed to"
						" allocate RX buffer\n");
				return -ENOMEM;
			}

			skb_copy_to_linear_data(skb, data, sizeof(avionics_data) + length);

			kfree(data);

			stats->rx_packets++;
			stats->rx_bytes += skb->len;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
			netif_rx_ni(skb);
#else
			netif_rx(skb);
#endif
		}

	}

	return 0;
}

static void hi6138_irq_worker(struct work_struct *work)
{
	struct hi6138 *hi6138;
	__u16 hirq_status;
	int err;

	hi6138 = container_of((struct work_struct*)work,
				  struct hi6138, worker);

	mutex_lock(&hi6138->lock);

	err = hi6138_get_fastaccess(hi6138->spi, HI6138_REG_HIRQ_PENDING,
					&hirq_status);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed read hirq pending register\n");
		goto done;
	}

    while(hirq_status) {
        if(hirq_status & HI6138_REG_HIRQ_MTIP) {
            err = hi6138_irq_bm(hi6138->bm);
            if (err < 0) {
                pr_err("avionics-hi6138: Bus Monitor IRQ failure\n");
            }
        }

		usleep_range(HI6138_RX_DELAY_MIN, HI6138_RX_DELAY_MAX);

        err = gpio_direction_output(hi6138->ackirq_gpio, 1);
        if (err < 0) {
            pr_err("avionics-hi6138: Failed to set gpio ackirq\n");
        }

        err = hi6138_get_fastaccess(hi6138->spi, HI6138_REG_HIRQ_PENDING,
                        &hirq_status);
        if (err < 0) {
            pr_err("avionics-hi6138: Failed read hirq pending register\n");
            goto done;
        }

        err = gpio_direction_output(hi6138->ackirq_gpio, 0);
        if (err < 0) {
            pr_err("avionics-hi6138: Failed to set gpio ackirq\n");
        }
    }

done:
	enable_irq(hi6138->irq);

	mutex_unlock(&hi6138->lock);
}

static irqreturn_t hi6138_irq(int irq, void *data)
{
	struct hi6138 *hi6138 = data;

	if (unlikely(irq != hi6138->irq)) {
		pr_err("avionics-hi6138: Unexpected irq %d\n", irq);
		return IRQ_HANDLED;
	}

	disable_irq_nosync(hi6138->irq);
	queue_work(hi6138->wq, &hi6138->worker);

	return IRQ_HANDLED;
}

static const struct net_device_ops hi6138_bm_netdev_ops = {
	.ndo_open = hi6138_bm_open,
	.ndo_stop = hi6138_bm_stop,
};

static const struct of_device_id hi6138_of_device_id[] = {
	{ .compatible	= "holt,hi6138" },
	{}
};
MODULE_DEVICE_TABLE(of, hi6138_of_device_id);

static const struct spi_device_id hi6138_spi_device_id[] = {
	{
		.name		= "hi6138",
		.driver_data	= (kernel_ulong_t)0,
	},
	{}
};
MODULE_DEVICE_TABLE(spi, hi6138_spi_device_id);

static int hi6138_get_config(struct spi_device *spi)
{
	struct hi6138 *hi6138 = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int err;

	hi6138->reset_gpio = of_get_named_gpio(dev->of_node, "reset-gpio", 0);
	if (hi6138->reset_gpio > 0 ) {
		if (!gpio_is_valid(hi6138->reset_gpio)) {
			pr_err("avionics-hi6138: Reset GPIO is not valid\n");
			return -EINVAL;
		}

		err = devm_gpio_request_one(&spi->dev, hi6138->reset_gpio,
						GPIOF_OUT_INIT_LOW, "hi6138-reset");
		if (err) {
			pr_err("avionics-hi6138: Failed to"
				   " register Reset GPIO\n");
			return err;
		}
	}

	hi6138->ackirq_gpio = of_get_named_gpio(dev->of_node, "ackirq-gpio", 0);
	if (hi6138->ackirq_gpio > 0 ) {
		if (!gpio_is_valid(hi6138->ackirq_gpio)) {
			pr_err("avionics-hi6138: ACKIRQ GPIO is not valid\n");
			return -EINVAL;
		}

		err = devm_gpio_request_one(&spi->dev, hi6138->ackirq_gpio,
						GPIOF_OUT_INIT_LOW, "hi6138-ackirq");
		if (err) {
			pr_err("avionics-hi6138: Failed to"
				   " register ACKIRQ GPIO\n");
			return err;
		}
	}

	hi6138->irq = irq_of_parse_and_map(dev->of_node, 0);
	if (hi6138->irq < 0) {
		pr_err("avionics-hi6138: Failed to get irq: %d\n",
			   hi6138->irq);
		return hi6138->irq;
	}

	err = request_irq(hi6138->irq, hi6138_irq,
			  IRQF_TRIGGER_FALLING | IRQF_ONESHOT | IRQF_NO_AUTOEN,
			  "hi6138", hi6138);
	if (err) {
		pr_err("avionics-hi6138: Failed to register"
			   " irq %d\n", hi6138->irq);
		return -EINVAL;
	}

	return 0;
}

static int hi6138_init_smt_mem(struct spi_device *spi)
{
	const __u16 base_addr = 0x00b0;
	__u16 smt_addr_list[8] = {
		HI6138_CMD_STACK_START,
		HI6138_CMD_STACK_START,
		HI6138_CMD_STACK_END,
		HI6138_CMD_STACK_IRQ,
		HI6138_DATA_STACK_START,
		HI6138_DATA_STACK_START,
		HI6138_DATA_STACK_END,
		HI6138_DATA_STACK_IRQ
	}, smt_addr_list_verify[8];
	int err;

	err = hi6138_set_fastaccess(spi, HI6138_REG_SMTSTART, base_addr);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed set SMT start address\n");
		return err;
	}

	err = hi6138_set_mem(spi, base_addr, smt_addr_list, 8);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed set configure SMT memory\n");
		return err;
	}

	err = hi6138_get_mem(spi, base_addr, smt_addr_list_verify, 8);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed get configure SMT memory\n");
		return err;
	}

	for (int i = 0; i < 8; i++) {
		if (smt_addr_list[i] != smt_addr_list_verify[i]) {
			pr_err("avionics-hi6138: Failed to set SMT addr %d: 0x%04x => 0x%04x\n",
					i, smt_addr_list[i], smt_addr_list_verify[i]);
		}
	}

	return 0;
}

static int hi6138_reset(struct spi_device *spi)
{
	struct hi6138 *hi6138 = spi_get_drvdata(spi);
	__u16 mcfg2;
	__u8 dev_id, rev_id;
	int err;

	pr_info("avionics-hi6138: Reseting Device\n");

	if (hi6138->reset_gpio <= 0) {
		pr_err("avionics-hi6138: no reset gpio configured\n");
		return -1;
	}

	err = gpio_direction_output(hi6138->reset_gpio, 0);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to set gpio reset\n");
		return err;
	}
	usleep_range(10000, 15000);

	err = gpio_direction_output(hi6138->reset_gpio, 1);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to clear gpio reset\n");
		return err;
	}
	usleep_range(10000, 15000);

	err = hi6138_get_reg(spi, HI6138_REG_MCFG2, &mcfg2);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed read master config register 2\n");
		return err;
	}

	dev_id = (mcfg2>>12)&0x03;
	rev_id = (mcfg2>>8)&0x0f;

	if (dev_id != 0x03) {
		pr_err("avionics-hi6138: Wrong Device ID: 0x%x,"
			   " this is the first verified access from this device"
			   " so this error could be due to an issue with the device or"
			   " the SPI bus.\n", dev_id);
		return -1;
	}

	if (rev_id != 0x01) {
		pr_err("avionics-hi6138: Wrong Revision ID: 0x%x\n", rev_id);
		return -1;
	}

	pr_info("avionics-hi6138: Device ID %d, Revision ID %d\n",
		dev_id, rev_id);

	err = hi6138_set_fastaccess(spi, HI6138_REG_MCFG1,
					HI6138_REG_MCFG1_TXINHA |
					HI6138_REG_MCFG1_TXINHB |
					HI6138_REG_MCFG1_INTSEL);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed set master config register 1\n");
		return err;
	}

	err = hi6138_set_fastaccess(spi, HI6138_REG_HIRQ_ENABLE,
					HI6138_REG_HIRQ_HSPINT |
					HI6138_REG_HIRQ_RAMPF |
					HI6138_REG_HIRQ_RAMIF |
					HI6138_REG_HIRQ_RTIP |
					HI6138_REG_HIRQ_MTIP |
					HI6138_REG_HIRQ_BCIP);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed set irq enable register\n");
		return err;
	}

	err = hi6138_set_fastaccess(spi, HI6138_REG_HIRQ_OUTPUT,
					HI6138_REG_HIRQ_HSPINT |
					HI6138_REG_HIRQ_RAMPF |
					HI6138_REG_HIRQ_RAMIF |
					HI6138_REG_HIRQ_RTIP |
					HI6138_REG_HIRQ_MTIP |
					HI6138_REG_HIRQ_BCIP);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed set irq output register\n");
		return err;
	}

	pr_info("avionics-hi6138: device reset\n");

	err = hi6138_init_smt_mem(spi);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to initialize SMT memory\n");
		return err;
	}

	err = hi6138_set_fastaccess(spi, HI6138_REG_TIME_TAG_CFG,
			HI6138_REG_TIME_TAG_CFG_MTTCK3); /* 100ns time tag clock */
	if (err < 0) {
		pr_err("avionics-hi6138-bm: Failed set Time Tag config register\n");
		return err;
	}

	return 0;
}

static struct avionics_mil1553bm avionics_mil1553bm_default = {
	.flags = 0,
};

static int hi6138_create_netdevs(struct spi_device *spi)
{
	struct hi6138 *hi6138 = spi_get_drvdata(spi);
	struct hi6138_priv *priv;
	int err;

	hi6138->wq = alloc_workqueue("hi6138", WQ_HIGHPRI, 0);
	if (!hi6138->wq) {
		pr_err("avionics-hi6138: Failed to allocate work-queue\n");
		return -ENOMEM;
	}
	INIT_WORK(&hi6138->worker, hi6138_irq_worker);

	hi6138->bm = avionics_device_alloc(sizeof(*priv),
					   &hi6138_mil553bm_ops);

	if (!hi6138->bm ) {
		pr_err("avionics-hi6138: Failed to allocate"
			   " Bus Monitor netdev\n");
		return -ENOMEM;
	}

	hi6138->bm->netdev_ops = &hi6138_bm_netdev_ops;
	priv = avionics_device_priv(hi6138->bm);

	if (!priv) {
		pr_err("avionics-hi6138: Failed to get private data"
			   " for Bus Monitor\n");
		return -EINVAL;
	}
	priv->dev = hi6138->bm;
	priv->spi = spi;
	priv->lock = &hi6138->lock;
	priv->bm_enabled = &hi6138->bm_enabled;
	skb_queue_head_init(&priv->skbq);

	err = hi6138_set_mil1553bm(&avionics_mil1553bm_default,
					hi6138->bm);
	if (err) {
		pr_err("avionics-hi6138: Failed to set Bus Monitor"
			   " default settings\n");
		return -EINVAL;
	}

	err = avionics_device_register(hi6138->bm);
	if (err) {
		pr_err("avionics-hi6138: Failed to register"
			   " Bus Monitor netdev\n");
		return -EINVAL;
	}


	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
static int hi6138_remove(struct spi_device *spi)
#else
static void hi6138_remove(struct spi_device *spi)
#endif
{
	struct hi6138 *hi6138 = spi_get_drvdata(spi);
	struct hi6138_priv *priv;

	pr_info("avionics-hi6138: Removing Device\n");

	if (hi6138->bm) {
		priv = avionics_device_priv(hi6138->bm);
		if (priv) {
			skb_queue_purge(&priv->skbq);
		}
		avionics_device_unregister(hi6138->bm);
		avionics_device_free(hi6138->bm);
		hi6138->bm = NULL;
	}

	if (hi6138->irq) {
		free_irq(hi6138->irq, hi6138);
	}

	if (hi6138->wq) {
		cancel_work_sync(&hi6138->worker);
	}

	if (hi6138->reset_gpio > 0) {
		if (gpio_direction_output(hi6138->reset_gpio, 1) < 0) {
			pr_err("avionics-hi6138: Failed to set gpio reset\n");
		}
		gpio_free(hi6138->reset_gpio);
		hi6138->reset_gpio = 0;
	}

	if (hi6138->ackirq_gpio > 0) {
		if (gpio_direction_output(hi6138->ackirq_gpio, 1) < 0) {
			pr_err("avionics-hi6138: Failed to set gpio ackirq\n");
		}
		gpio_free(hi6138->ackirq_gpio);
		hi6138->ackirq_gpio = 0;
	}

	if (hi6138->wq) {
		flush_scheduled_work();
		flush_workqueue(hi6138->wq);
		destroy_workqueue(hi6138->wq);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
	return 0;
#endif
}

static int hi6138_probe(struct spi_device *spi)
{
	struct hi6138 *hi6138;
	struct device *dev = &spi->dev;
	int err;

	pr_info("avionics-hi6138: Adding Device\n");

	hi6138 = devm_kzalloc(dev, sizeof(*hi6138), GFP_KERNEL);
	if (!hi6138) {
		pr_err("avionics-hi6138: Failed to allocate hi6138 memory\n");
		return -ENOMEM;
	}
	spi_set_drvdata(spi, hi6138);
	mutex_init(&hi6138->lock);
	atomic_set(&hi6138->bm_enabled, 0);
	hi6138->spi = spi;

	err = hi6138_get_config(spi);
	if (err) {
		pr_err("avionics-hi6138: Failed to get system configuration"
			   " from dts file: %d\n",err);
		hi6138_remove(spi);
		return err;
	}

	err = hi6138_reset(spi);
	if (err) {
		pr_err("avionics-hi6138: Failed to bring device"
			   " out of reset: %d\n",err);
		hi6138_remove(spi);
		return err;
	}

	err = hi6138_create_netdevs(spi);
	if (err) {
		pr_err("avionics-hi6138: Failed to"
			   " register netdevs: %d\n", err);
		hi6138_remove(spi);
		return err;
	}

	mutex_lock(&hi6138->lock);

	enable_irq(hi6138->irq);

	err = gpio_direction_output(hi6138->ackirq_gpio, 1);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to set gpio ackirq\n");
		return err;
	}
	usleep_range(1000, 10000);
	err = gpio_direction_output(hi6138->ackirq_gpio, 0);
	if (err < 0) {
		pr_err("avionics-hi6138: Failed to set gpio ackirq\n");
		return err;
	}

	mutex_unlock(&hi6138->lock);

	return 0;
}

static struct spi_driver hi6138_spi_driver = {
	.driver = {
		.name = "hi6138",
		.of_match_table = hi6138_of_device_id,
	},
	.id_table = hi6138_spi_device_id,
	.probe = hi6138_probe,
	.remove = hi6138_remove,
};
module_spi_driver(hi6138_spi_driver);
