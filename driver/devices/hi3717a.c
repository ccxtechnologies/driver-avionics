/*
 * Copyright (C), 2019-2021 CCX Technologies
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
#include <linux/atomic.h>
#include <linux/interrupt.h>
#include <linux/version.h>

#include "avionics.h"
#include "avionics-device.h"

MODULE_DESCRIPTION("HOLT Hi-3717A ARINC-717 Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.1.0");

#define HI3717A_FIFO_DEPTH	32
#define HI3717A_SAMPLE_SIZE	(sizeof(avionics_data))
#define HI3717A_MTU		(HI3717A_FIFO_DEPTH * HI3717A_SAMPLE_SIZE * 8)

#define HI3717A_OPCODE_RD_CTRL0		0xe4
#define HI3717A_OPCODE_WR_CTRL0		0x64

#define HI3717A_OPCODE_RD_CTRL1		0xe2
#define HI3717A_OPCODE_WR_CTRL1		0x62

#define HI3717A_OPCODE_RD_RXFSTAT	0xe6
#define HI3717A_OPCODE_RD_TXFSTAT	0xe8

#define HI3717A_OPCODE_RD_FSPIN		0xea
#define HI3717A_OPCODE_WR_FSPIN		0x6a

#define HI3717A_OPCODE_RD_WRDCNT	0xf2
#define HI3717A_OPCODE_WR_WRDCNT	0x72

#define HI3717A_OPCODE_WR_TXFIFO	0x74
#define HI3717A_OPCODE_RD_RXFIFO	0xfe


#define HI3717A_RXFIFO_INSYNC	0x80
#define HI3717A_RXFIFO_FULL	0x10
#define HI3717A_RXFIFO_HALF	0x08
#define HI3717A_RXFIFO_EMPTY	0x04
#define HI3717A_RXFIFO_OVF	0x02

#define HI3717A_TXFIFO_EMPTY	0x20
#define HI3717A_TXFIFO_FULL	0x80

#define HI3717A_NUM_TX	1
#define HI3717A_NUM_RX	1

struct hi3717a {
	struct net_device *rx[HI3717A_NUM_RX];
	struct net_device *tx[HI3717A_NUM_TX];
	struct workqueue_struct *wq;
	int reset_gpio;
	int irq;
	struct mutex lock;
	atomic_t tx_enabled;
	atomic_t rx_enabled;
	int period_usec;
};

struct hi3717a_priv {
	struct net_device *dev;
	struct spi_device *spi;
	struct mutex *lock;
	struct workqueue_struct *wq;
	struct delayed_work worker;
	int irq;
	int reset_gpio;
	__u16 *tx_buffer;
	int tx_buffer_size;
	atomic_t *tx_enabled;
	atomic_t *rx_enabled;
	int *period_usec;
	struct spi_transfer opcodes[HI3717A_FIFO_DEPTH];
};

static ssize_t hi3717a_get_cntrl(struct hi3717a_priv *priv, __u8 opcode)
{
	return spi_w8r8(priv->spi, opcode);
}

static int hi3717a_set_cntrl(struct hi3717a_priv *priv, __u8 value, __u8 mask,
			      __u8 wr_opcode, __u8 rd_opcode)
{
	ssize_t status;
	__u8 wr_cmd[2];
	int err;

	mutex_lock(priv->lock);

	status = hi3717a_get_cntrl(priv, rd_opcode);
	if (status < 0) {
		pr_err("avionics-hi3717a: Failed to read ctrl 0x%x: %zd\n",
		       rd_opcode, status);
		mutex_unlock(priv->lock);
		return -ENODEV;
	}

	wr_cmd[0] = wr_opcode;

	wr_cmd[1] = (status&(~mask)) | (value&mask);
	err = spi_write(priv->spi, wr_cmd, sizeof(wr_cmd));
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to set ctrl %hhn\n", wr_cmd);
		mutex_unlock(priv->lock);
		return err;
	}

	status = hi3717a_get_cntrl(priv, rd_opcode);
	if (status < 0) {
		pr_err("avionics-hi3717a: Failed to read ctrl %d: %zd\n",
		       rd_opcode, status);
		mutex_unlock(priv->lock);
		return -ENODEV;
	}

	if ((status&mask) != (value&mask)) {
		pr_err("avionics-hi3717a: Failed to set"
		       " ctrl %d to %d & %d : %zd\n",
		       wr_cmd[0], value, mask, status);
		mutex_unlock(priv->lock);
		return -ENODEV;
	}

	mutex_unlock(priv->lock);
	return 0;
}

static int hi3717a_set_rate(struct avionics_rate *rate,
			   const struct net_device *dev)
{
	struct hi3717a_priv *priv;
	__u8 value;
	ssize_t ctrl0, ctrl1, fspin, wrdcnt;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return -EINVAL;
	}

	if (atomic_read(priv->tx_enabled)) {
		pr_err("avionics-hi3717a: Can't change rate while"
		       " transmitter is up\n");
		return -EINVAL;
	}

	if(rate->rate_hz == 384) {
		value = 1<<3;
	} else if(rate->rate_hz == 768) {
		value = 0;
	} else if(rate->rate_hz == 1536) {
		value = 1<<4;
	} else if(rate->rate_hz == 3072) {
		value = 2<<4;
	} else if(rate->rate_hz == 6144) {
		value = 3<<4;
	} else if(rate->rate_hz == 12288) {
		value = 4<<4;
	} else if(rate->rate_hz == 24576) {
		value = 5<<4;
	} else if(rate->rate_hz == 49152) {
		value = 6<<4;
	} else if(rate->rate_hz == 98304) {
		value = 7<<4;
	} else {
		pr_warn("avionics-hi3717a: speed must be  384, 768, 1536, 3072,"
			" 6144, 12288, 24576, 49152, or 98304 Hz\n");
		return -EINVAL;
	}

	ctrl0 = hi3717a_get_cntrl(priv, HI3717A_OPCODE_RD_CTRL0);
	if (ctrl0 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL0\n");
		return ctrl0;
	}

	if ((ctrl0&0x78) == value) {
		return 0;
	}

	pr_warn("avionics-hi3717a: resetting device to change speed\n");

	ctrl1 = hi3717a_get_cntrl(priv, HI3717A_OPCODE_RD_CTRL1);
	if (ctrl1 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL1\n");
		return ctrl1;
	}

	fspin = hi3717a_get_cntrl(priv, HI3717A_OPCODE_RD_FSPIN);
	if (fspin < 0) {
		pr_err("avionics-hi3717a: Failed to read FSPIN\n");
		return fspin;
	}

	wrdcnt = hi3717a_get_cntrl(priv, HI3717A_OPCODE_RD_WRDCNT);
	if (wrdcnt < 0) {
		pr_err("avionics-hi3717a: Failed to read WRDCNT\n");
		return wrdcnt;
	}

	mutex_lock(priv->lock);

	gpio_set_value(priv->reset_gpio, 0);
	usleep_range(10, 100);
	gpio_set_value(priv->reset_gpio, 1);

	mutex_unlock(priv->lock);

	err = hi3717a_set_cntrl(priv, wrdcnt, 0xff,
			  HI3717A_OPCODE_WR_WRDCNT, HI3717A_OPCODE_RD_WRDCNT);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to reset WRDCNT\n");
		return err;
	}
	pr_info("avionics-hi3717a: Reloaded WRDCNT with 0x%zx\n", wrdcnt);

	err = hi3717a_set_cntrl(priv, fspin, 0xff,
			  HI3717A_OPCODE_WR_FSPIN, HI3717A_OPCODE_RD_FSPIN);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to reset FSPIN\n");
		return err;
	}
	pr_info("avionics-hi3717a: Reloaded FSPIN with 0x%zx\n", fspin);

	err = hi3717a_set_cntrl(priv, ctrl1, 0xff,
			  HI3717A_OPCODE_WR_CTRL1, HI3717A_OPCODE_RD_CTRL1);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to reset CTRL1\n");
		return err;
	}
	pr_info("avionics-hi3717a: Reloaded CNTRL1 with 0x%zx\n", ctrl1);

	err = hi3717a_set_cntrl(priv, (ctrl0&(~0x78)) | (value&0x78) , 0x7f,
			  HI3717A_OPCODE_WR_CTRL0, HI3717A_OPCODE_RD_CTRL0);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to set CTRL0\n");
		return err;
	}
	pr_info("avionics-hi3717a: Reloaded CNTRL0 with 0x%zx\n",
		(ctrl0&(~0x78)) | (value&0x78));

	*priv->period_usec = 1000000/(rate->rate_hz/12);

	return 0;
}

static void hi3717a_get_rate(struct avionics_rate *rate,
			    const struct net_device *dev)
{
	struct hi3717a_priv *priv;
	ssize_t status;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return;
	}

	status = hi3717a_get_cntrl(priv, HI3717A_OPCODE_RD_CTRL0);
	if (status < 0) {
		pr_err("avionics-hi3717a: Failed to get rate: %zd\n", status);
	} else if(status&0x0008) {
		rate->rate_hz = 384;
	} else if((status&0x0070) == 0) {
		rate->rate_hz = 768;
	} else if((status&0x0070) == (1<<4)) {
		rate->rate_hz = 1536;
	} else if((status&0x0070) == (2<<4)) {
		rate->rate_hz = 3072;
	} else if((status&0x0070) == (3<<4)) {
		rate->rate_hz = 6144;
	} else if((status&0x0070) == (4<<4)) {
		rate->rate_hz = 12288;
	} else if((status&0x0070) == (5<<4)) {
		rate->rate_hz = 24576;
	} else if((status&0x0070) == (6<<4)) {
		rate->rate_hz = 49152;
	} else if((status&0x0070) == (7<<4)) {
		rate->rate_hz = 98304;
	}
}

static void hi3717a_get_arinc717rx(struct avionics_arinc717rx *config,
				  const struct net_device *dev)
{
	struct hi3717a_priv *priv;
	ssize_t ctrl0, ctrl1;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
	}

	ctrl0 = hi3717a_get_cntrl(priv, HI3717A_OPCODE_RD_CTRL0);
	if (ctrl0 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL0\n");
	}

	ctrl1 = hi3717a_get_cntrl(priv, HI3717A_OPCODE_RD_CTRL1);
	if (ctrl1 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL1\n");
	}

	config->flags = (ctrl0&0x01)|(ctrl1&0x06);

}

static int hi3717a_set_arinc717rx(struct avionics_arinc717rx *config,
				 const struct net_device *dev)
{
	struct hi3717a_priv *priv;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return -ENODEV;
	}

	err = hi3717a_set_cntrl(priv, config->flags, 0x01,
			      HI3717A_OPCODE_WR_CTRL0, HI3717A_OPCODE_RD_CTRL0);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to set CTRL0\n");
		return err;
	}

	err = hi3717a_set_cntrl(priv, config->flags, 0x06,
			      HI3717A_OPCODE_WR_CTRL1, HI3717A_OPCODE_RD_CTRL1);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to set CTRL1\n");
		return err;
	}

	return 0;
}

static void hi3717a_get_arinc717tx(struct avionics_arinc717tx *config,
				  const struct net_device *dev)
{
	struct hi3717a_priv *priv;
	ssize_t ctrl0, ctrl1;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
	}

	ctrl0 = hi3717a_get_cntrl(priv, HI3717A_OPCODE_RD_CTRL0);
	if (ctrl0 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL0\n");
	}

	ctrl1 = hi3717a_get_cntrl(priv, HI3717A_OPCODE_RD_CTRL1);
	if (ctrl1 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL1\n");
	}

	config->flags = (ctrl0&0x06)|(ctrl1&0x01);

}

static int hi3717a_set_arinc717tx(struct avionics_arinc717tx *config,
				 const struct net_device *dev)
{
	struct hi3717a_priv *priv;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return -ENODEV;
	}


	err = hi3717a_set_cntrl(priv, config->flags, 0x06,
			      HI3717A_OPCODE_WR_CTRL0, HI3717A_OPCODE_RD_CTRL0);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to set CTRL0\n");
		return err;
	}

	err = hi3717a_set_cntrl(priv, config->flags, 0x01,
			      HI3717A_OPCODE_WR_CTRL1, HI3717A_OPCODE_RD_CTRL1);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to set CTRL1\n");
		return err;
	}

	return 0;
}

static struct avionics_ops hi3717a_arinc717rx_ops = {
	.name = "arinc717rx%d",
	.set_rate = hi3717a_set_rate,
	.get_rate = hi3717a_get_rate,
	.get_arinc717rx = hi3717a_get_arinc717rx,
	.set_arinc717rx = hi3717a_set_arinc717rx,
};

static struct avionics_ops hi3717a_arinc717tx_ops = {
	.name = "arinc717tx%d",
	.set_rate = hi3717a_set_rate,
	.get_rate = hi3717a_get_rate,
	.get_arinc717tx = hi3717a_get_arinc717tx,
	.set_arinc717tx = hi3717a_set_arinc717tx,
};

static int hi3717a_change_mtu(struct net_device *dev, int mtu)
{
	if (mtu != HI3717A_MTU) {
		pr_err("avionics-hi3717a: MTU must be %zd.\n", HI3717A_MTU);
		return -EINVAL;
	}

	return 0;
}

static void hi3717a_tx_worker(struct work_struct *work)
{
	struct net_device *dev;
	struct net_device_stats *stats;
	struct hi3717a_priv *priv;
	__u8 wr_cmd[3];
	ssize_t status;
	int err, i, delay, frame_size;
	__u16 *tx_buffer, vbuffer;

	priv = container_of((struct delayed_work*)work,
			    struct hi3717a_priv, worker);
	dev = priv->dev;
	stats = &dev->stats;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return;
	}

	tx_buffer = priv->tx_buffer;

	frame_size = priv->tx_buffer_size/4;
	delay = (*priv->period_usec)*8;
	wr_cmd[0] = HI3717A_OPCODE_WR_TXFIFO;
	i = 0;

	/* Set frame markers */
	tx_buffer[frame_size*0] = 01107;
	tx_buffer[frame_size*1] = 02670;
	tx_buffer[frame_size*2] = 05107;
	tx_buffer[frame_size*3] = 06670;

	while (atomic_read(priv->tx_enabled)) {

		while(1) {
			mutex_lock(priv->lock);
			status = hi3717a_get_cntrl(priv,
						   HI3717A_OPCODE_RD_TXFSTAT);
			mutex_unlock(priv->lock);

			if (status < 0) {
				pr_err("avionics-hi3717a:"
				       " Failed to read status\n");
				goto done;
			}

			if (status & HI3717A_TXFIFO_EMPTY) {
				pr_warn("avionics-hi3717a: TX FIFO Empty\n");
				stats->tx_errors++;
				stats->tx_fifo_errors++;
			}

			if (status & HI3717A_TXFIFO_FULL) {
				break;
			}

			vbuffer = cpu_to_be16(tx_buffer[i]);
			wr_cmd[1] = (vbuffer&0x00ff);
			wr_cmd[2] = (vbuffer&0xff00)>>8;

			mutex_lock(priv->lock);
			err = spi_write(priv->spi, &wr_cmd, sizeof(wr_cmd));
			mutex_unlock(priv->lock);

			if (err < 0) {
				pr_err("avionics-hi3717a: Failed to load"
				       " tx fifo\n");
				goto done;
			}

			stats->tx_bytes += 2;
			if (i < (priv->tx_buffer_size-1)) {
				i++;
			} else {
				i = 0;
				stats->tx_packets++;
			}
		}

		usleep_range(delay, delay+100);
	}

done:
	kfree(tx_buffer);

}

static int hi3717a_tx_open(struct net_device *dev)
{
	struct hi3717a_priv *priv;
	struct avionics_rate rate;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return -EINVAL;
	}

	if (atomic_read(priv->tx_enabled)) {
		pr_err("avionics-hi3717a: Transimitter already running\n");
		return 0;
	}

	hi3717a_get_rate(&rate, dev);
	priv->tx_buffer_size = (rate.rate_hz/12)*4;

	priv->tx_buffer = kzalloc(priv->tx_buffer_size*sizeof(__u16),
				     GFP_KERNEL);
	if (!priv->tx_buffer) {
		pr_err("avionics-hi3717a: Failed to allocate tx buffer\n");
		return -ENOMEM;
	}

	atomic_set(priv->tx_enabled, 1);

	pr_warn("avionics-hi3717a: Enabling Driver\n");
	netif_wake_queue(dev);

	queue_delayed_work(priv->wq, &priv->worker, 0);

	return 0;
}

static int hi3717a_tx_stop(struct net_device *dev)
{
	struct hi3717a_priv *priv;

	pr_warn("avionics-hi3717a: Disabling Driver\n");

	netif_stop_queue(dev);

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return -EINVAL;
	}

	atomic_set(priv->tx_enabled, 0);
	priv->tx_buffer_size = 0;
	priv->tx_buffer = NULL;

	return 0;
}

static int hi3717a_rx_open(struct net_device *dev)
{
	struct hi3717a_priv *priv;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return -EINVAL;
	}

	if (atomic_read(priv->rx_enabled)) {
		pr_err("avionics-hi3717a: Receiver already running\n");
		return 0;
	}

	atomic_set(priv->rx_enabled, 1);
	enable_irq(priv->irq);

	return 0;
}

static int hi3717a_rx_stop(struct net_device *dev)
{
	struct hi3717a_priv *priv;

	pr_warn("avionics-hi3717a: Disabling Receiver\n");

	netif_stop_queue(dev);

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return -EINVAL;
	}

	atomic_set(priv->rx_enabled, 0);
	disable_irq(priv->irq);

	return 0;
}

static int hi3717a_rxfifo_is_empty(struct hi3717a_priv *priv)
{
	int status;
	struct net_device *dev;
	struct net_device_stats *stats;

	dev = priv->dev;
	stats = &dev->stats;

	status = hi3717a_get_cntrl(priv, HI3717A_OPCODE_RD_RXFSTAT);
	if (unlikely(status < 0)) {
		pr_err("avionics-hi3717a: Failed to read status\n");
		return status;
	}

	if (!(status & HI3717A_RXFIFO_INSYNC)) {
		pr_err("avionics-hi3717a: RX Out of sync\n");
		stats->rx_errors++;
		stats->rx_fifo_errors++;
	}

	if (status & HI3717A_RXFIFO_EMPTY) {
		return HI3717A_RXFIFO_EMPTY;
	}

	if (status & HI3717A_RXFIFO_OVF) {
		pr_err("avionics-hi3717a: RX FIFO Overflow\n");
		stats->rx_errors++;
		stats->rx_fifo_errors++;
		return HI3717A_RXFIFO_OVF;
	}

	return 0;
}


static int hi3717a_rxfifo_read(struct hi3717a_priv *priv,
		avionics_data *values, unsigned num_reads)
{
	int i, status;
	struct spi_message message;
	struct spi_transfer *opcodes = priv->opcodes;
	__u8 rd_cmd[5], buffer[HI3717A_FIFO_DEPTH*5];
	__u32 vbuffer;
	__u64 time_msecs;
	struct timespec64 tv;

	spi_message_init(&message);
	memset(opcodes, 0, sizeof(*opcodes));

	rd_cmd[0] = HI3717A_OPCODE_RD_RXFIFO;

	for(i = 0; i < num_reads; i++) {
		opcodes[i].len = 5;
		opcodes[i].tx_buf = rd_cmd;
		opcodes[i].rx_buf = &buffer[i*5];
		if(i < (num_reads-1)) {
			opcodes[i].cs_change = 1;
		}
		spi_message_add_tail(&opcodes[i], &message);
	}

	ktime_get_real_ts64(&tv);
	time_msecs = (tv.tv_sec*MSEC_PER_SEC) + (tv.tv_nsec/NSEC_PER_MSEC);
	status = spi_sync(priv->spi, &message);

	for(i = 0; i < num_reads; i++) {
		vbuffer = buffer[i*5+1] + (buffer[i*5+2]<<8) +
			(buffer[i*5+3]<<16) + (buffer[i*5+4]<<24);
		values[i].value = be32_to_cpu(vbuffer);
		values[i].time_msecs = time_msecs;
	}

	if(status < 0) {
		return status;
	} else {
		return num_reads;
	}
}

static int hi3717a_rxfifo_read_all(struct hi3717a_priv *priv,
				   avionics_data *data)
{
	int count = 0, status;
	struct spi_message message;
	struct spi_transfer opcodes[3];
	__u8 rd_cmd[5], rd_buffer[5], stats_cmd[2], stats_buffer[2][2];
	__u32 vbuffer;
	__u64 time_msecs;
	struct timespec64 tv;

	spi_message_init(&message);
	memset(opcodes, 0, sizeof(opcodes));

	stats_cmd[0] = HI3717A_OPCODE_RD_RXFSTAT;
	rd_cmd[0] = HI3717A_OPCODE_RD_RXFIFO;

	opcodes[0].len = 2;
	opcodes[0].tx_buf = stats_cmd;
	opcodes[0].rx_buf = stats_buffer[0];
	opcodes[0].cs_change = 1;
	spi_message_add_tail(&opcodes[0], &message);

	opcodes[1].len = 5;
	opcodes[1].tx_buf = rd_cmd;
	opcodes[1].rx_buf = rd_buffer;
	opcodes[1].cs_change = 1;
	spi_message_add_tail(&opcodes[1], &message);

	opcodes[2].len = 2;
	opcodes[2].tx_buf = stats_cmd;
	opcodes[2].rx_buf = stats_buffer[1];
	spi_message_add_tail(&opcodes[2], &message);

	ktime_get_real_ts64(&tv);
	time_msecs = (tv.tv_sec*MSEC_PER_SEC) + (tv.tv_nsec/NSEC_PER_MSEC);
	while(count < HI3717A_FIFO_DEPTH) {

		status = spi_sync(priv->spi, &message);
		if(status < 0) {
			return status;
		}

		if(!(stats_buffer[0][1] & HI3717A_RXFIFO_EMPTY)) {
			vbuffer = rd_buffer[1] + (rd_buffer[2]<<8) +
				(rd_buffer[3]<<16) + (rd_buffer[4]<<24);
			data[count].value = be32_to_cpu(vbuffer);
			data[count].time_msecs = time_msecs;
			count++;
		}

		if(stats_buffer[1][1] & HI3717A_RXFIFO_EMPTY) {
			break;
		}

	}

	return count;
}

static int hi3717a_rx_send_upstream(struct hi3717a_priv *priv,
				    avionics_data *data, int count)
{
	struct sk_buff *skb;
	struct net_device *dev;
	struct net_device_stats *stats;

	dev = priv->dev;
	stats = &dev->stats;

	skb = avionics_device_alloc_skb(dev, count*sizeof(data[0]));
	if (unlikely(!skb)) {
		pr_err("avionics-hi3717a: Failed to allocate RX buffer\n");
		return -ENOMEM;
	}

	skb_copy_to_linear_data(skb, (void*)data, count*sizeof(data[0]));

	stats->rx_packets++;
	stats->rx_bytes += skb->len;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
	netif_rx_ni(skb);
#else
	netif_rx(skb);
#endif

	return 0;
}

#define HI3717A_RX_WORDS_PER 16

static void hi3717a_rx_worker(struct work_struct *work)
{
	struct hi3717a_priv *priv;
	struct net_device *dev;
	avionics_data *data;
	ssize_t status;
	int count;
	bool fifo_error = false;

	priv = container_of((struct delayed_work*)work,
			    struct hi3717a_priv, worker);
	dev = priv->dev;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		goto done_irq;
	}

	mutex_lock(priv->lock);
	status = hi3717a_rxfifo_is_empty(priv);
	if (unlikely(status < 0)) {
		pr_err("avionics-hi3717a: Failed to read status\n");
		goto done_mutex;
	} else if (status == HI3717A_RXFIFO_EMPTY) {
		goto done_mutex;
	} else if (status == HI3717A_RXFIFO_OVF) {
		fifo_error = 1;
	}

	data = kmalloc(HI3717A_MTU, GFP_KERNEL);
	if (data == NULL) {
		pr_err("avionics-hi3593: Failed to allocate data buffer\n");
		return;
	}

	status = hi3717a_rxfifo_read(priv, data, HI3717A_RX_WORDS_PER);
	if (unlikely(status < 0)) {
		pr_err("avionics-hi3717a: Failed to read fifo block\n");
		goto done;
	}

	count = status;

	status = hi3717a_rxfifo_read_all(priv, &data[count]);
	if (unlikely(status < 0)) {
		pr_err("avionics-hi3717a: Failed to empty fifo\n");
		goto done;
	}

	count += status;

	if (!fifo_error) {
		status = hi3717a_rx_send_upstream(priv, data, count);
		if (unlikely(status < 0)) {
			pr_err("avionics-hi3717a: Failed to send packet\n");
			goto done;
		}
	}

done:
	kfree(data);
done_mutex:
	mutex_unlock(priv->lock);
done_irq:
	enable_irq(priv->irq);
}

static irqreturn_t hi3717a_rx_irq(int irq, void *data)
{
	struct hi3717a_priv *priv = data;
	int delay;

	if (unlikely(irq != priv->irq)) {
		pr_err("avionics-hi3717a: Unexpected irq %d\n", irq);
		return IRQ_HANDLED;
	}

	disable_irq_nosync(priv->irq);


	if (atomic_read(priv->rx_enabled)) {
		delay = (*priv->period_usec)*(HI3717A_RX_WORDS_PER) +
			(*priv->period_usec);
		queue_delayed_work(priv->wq, &priv->worker,
				   (delay*HZ)/1000000);
	}

	return IRQ_HANDLED;
}

static netdev_tx_t hi3717a_tx_start_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	struct hi3717a_priv *priv;
	avionics_data data;
	__u16 frame, word_count, word;
	int offset, i;

	if (skb->protocol != htons(ETH_P_AVIONICS)) {
		kfree_skb(skb);
		stats->tx_dropped++;
		return NETDEV_TX_OK;
	}

	if (unlikely(skb->len > HI3717A_MTU)) {
		kfree_skb(skb);
		stats->tx_dropped++;
		return NETDEV_TX_OK;
	}

	if (unlikely(skb->len % 4)) {
		kfree_skb(skb);
		stats->tx_dropped++;
		return NETDEV_TX_OK;
	}

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		kfree_skb(skb);
		stats->tx_dropped++;
		return NETDEV_TX_OK;
	}

	/* word format:
	 * 0000yyyy yyyyyyyy xxxxxxxx xxxxx0zz
	 * where y is the word to write (12 bits)
	 * where x is the word count starting at 1
	 * and z if the frame starting at 0*/

	for (i = 0; i < skb->len; i = i + sizeof(data)) {
		/* ARINC-717 doesn't use the transmit timestamp for anything */

		memcpy(&data, &skb->data[i], sizeof(data));

		word = (data.value&0x0fff0000)>>16;
		word_count = (data.value&0x0000fff8)>>3;
		frame = data.value&0x00000003;

		offset = (frame * priv->tx_buffer_size/4) + (word_count-1);

		if ((word_count > 1) && (offset < priv->tx_buffer_size)) {
			priv->tx_buffer[offset] = word;
		}
	}

	consume_skb(skb);

	return NETDEV_TX_OK;
}

static const struct net_device_ops hi3717a_tx_netdev_ops = {
	.ndo_change_mtu = hi3717a_change_mtu,
	.ndo_open = hi3717a_tx_open,
	.ndo_stop = hi3717a_tx_stop,
	.ndo_start_xmit = hi3717a_tx_start_xmit,
};

static const struct net_device_ops hi3717a_rx_netdev_ops = {
	.ndo_change_mtu = hi3717a_change_mtu,
	.ndo_open = hi3717a_rx_open,
	.ndo_stop = hi3717a_rx_stop,
};

static const struct of_device_id hi3717a_of_device_id[] = {
	{ .compatible	= "holt,hi3717a" },
	{}
};
MODULE_DEVICE_TABLE(of, hi3717a_of_device_id);

static const struct spi_device_id hi3717a_spi_device_id[] = {
	{
		.name		= "hi3717a",
		.driver_data	= (kernel_ulong_t)0,
	},
	{}
};
MODULE_DEVICE_TABLE(spi, hi3717a_spi_device_id);

static int hi3717a_get_config(struct spi_device *spi)
{
	struct hi3717a *hi3717a = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int err;

	hi3717a->reset_gpio = of_get_named_gpio(dev->of_node, "reset-gpio", 0);
	if (hi3717a->reset_gpio > 0 ) {
		if (!gpio_is_valid(hi3717a->reset_gpio)) {
			pr_err("avionics-hi3717a: Reset GPIO is not valid\n");
			return -EINVAL;
		}

		err = devm_gpio_request_one(&spi->dev, hi3717a->reset_gpio,
					    GPIOF_OUT_INIT_HIGH, "reset");
		if (err) {
			pr_err("avionics-hi3717a: Failed to"
			       " register Reset GPIO\n");
			return err;
		}
	}

	hi3717a->irq = irq_of_parse_and_map(dev->of_node, 0);
	if (hi3717a->irq < 0) {
		pr_err("avionics-hi3717a: Failed to"
		       " get irq: %d\n", hi3717a->irq);
		return hi3717a->irq;
	}

	return 0;
}

static int hi3717a_reset(struct spi_device *spi)
{
	struct hi3717a *hi3717a = spi_get_drvdata(spi);
	ssize_t status;

	gpio_set_value(hi3717a->reset_gpio, 0);
	usleep_range(10, 100);
	gpio_set_value(hi3717a->reset_gpio, 1);

	status = spi_w8r8(spi, HI3717A_OPCODE_RD_TXFSTAT);
	if (status != 0x20) {
		pr_err("avionics-hi3717a: TX FIFO is not cleared: %zx\n",
		       status);
		return -ENODEV;
	}

	pr_info("avionics-hi3717a: Device up\n");
	return 0;
}

static struct avionics_arinc717rx avionics_arinc717rx_default = {
	.flags = 0,
};

static struct avionics_arinc717tx avionics_arinc717tx_default = {
	.flags = AVIONICS_ARINC717TX_SLEW&(1<<1), /* default to 3.75us slew rate */
};

static int hi3717a_create_netdevs(struct spi_device *spi)
{
	struct hi3717a *hi3717a = spi_get_drvdata(spi);
	struct hi3717a_priv *priv;
	int i, err;

	hi3717a->period_usec = 1000000/64; /* default rate is 64 words/sec */
	hi3717a->wq = alloc_workqueue("hi3717a", WQ_HIGHPRI, 0);
	if (!hi3717a->wq) {
		pr_err("avionics-hi3717a: Failed to allocate work-queue\n");
		return -ENOMEM;
	}

	for (i = 0; i < HI3717A_NUM_TX; i++) {
		hi3717a->tx[i] = avionics_device_alloc(sizeof(*priv),
						      &hi3717a_arinc717tx_ops);

		if (!hi3717a->tx[i] ) {
			pr_err("avionics-hi3717a: Failed to allocate"
			       " TX %d netdev\n", i);
			return -ENOMEM;
		}

		hi3717a->tx[i]->netdev_ops = &hi3717a_tx_netdev_ops;
		hi3717a->tx[i]->mtu = HI3717A_MTU;
		priv = avionics_device_priv(hi3717a->tx[i]);
		if (!priv) {
			pr_err("avionics-hi3717a: Failed to get private data"
			       " for TX %d\n", i);
			return -EINVAL;
		}

		priv->dev = hi3717a->tx[i];
		priv->spi = spi;
		priv->lock = &hi3717a->lock;
		priv->reset_gpio = hi3717a->reset_gpio;
		priv->tx_buffer = NULL;
		priv->tx_enabled = &hi3717a->tx_enabled;
		priv->wq = hi3717a->wq;
		priv->period_usec = &hi3717a->period_usec;

		INIT_DELAYED_WORK(&priv->worker, hi3717a_tx_worker);

		err = hi3717a_set_arinc717tx(&avionics_arinc717tx_default,
					    hi3717a->tx[i]);
		if (err) {
			pr_err("avionics-hi3717a: Failed to set TX %d"
			       " default settings\n", i);
			return -EINVAL;
		}

		err = avionics_device_register(hi3717a->tx[i]);
		if (err) {
			pr_err("avionics-hi3717a: Failed to register"
			       " TX %d netdev\n", i);
			return -EINVAL;
		}

	}

	for (i = 0; i < HI3717A_NUM_RX; i++) {
		hi3717a->rx[i] = avionics_device_alloc(sizeof(*priv),
						      &hi3717a_arinc717rx_ops);
		if (!hi3717a->rx[i] ) {
			pr_err("avionics-hi3717a: Failed to allocate"
			       " RX %d netdev\n", i);
			return -ENOMEM;
		}

		hi3717a->rx[i]->netdev_ops = &hi3717a_rx_netdev_ops;
		hi3717a->rx[i]->mtu = HI3717A_MTU;
		priv = avionics_device_priv(hi3717a->rx[i]);
		if (!priv) {
			pr_err("avionics-hi3717a: Failed to get private data"
			       " for RX %d\n", i);
			return -EINVAL;
		}

		priv->dev = hi3717a->rx[i];
		priv->spi = spi;
		priv->lock = &hi3717a->lock;
		priv->reset_gpio = hi3717a->reset_gpio;
		priv->tx_enabled = &hi3717a->tx_enabled;
		priv->tx_buffer = NULL;
		priv->rx_enabled = &hi3717a->rx_enabled;
		priv->wq = hi3717a->wq;
		priv->period_usec = &hi3717a->period_usec;

		INIT_DELAYED_WORK(&priv->worker, hi3717a_rx_worker);

		err = request_irq(hi3717a->irq, hi3717a_rx_irq,
				  IRQF_TRIGGER_LOW,
				  hi3717a->rx[i]->name, priv);
		if (err) {
			pr_err("avionics-hi3717a: Failed to register"
			       " RX %d irq %d\n", i, hi3717a->irq);
			return -EINVAL;
		}
		priv->irq = hi3717a->irq;
		disable_irq_nosync(priv->irq);

		err = hi3717a_set_arinc717rx(&avionics_arinc717rx_default,
					    hi3717a->rx[i]);
		if (err) {
			pr_err("avionics-hi3717a: Failed to set RX %d"
			       " default settings\n", i);
			return -EINVAL;
		}

		err = avionics_device_register(hi3717a->rx[i]);
		if (err) {
			pr_err("avionics-hi3717a: Failed to register"
			       " RX %d netdev\n", i);
			return -EINVAL;
		}

	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
static int hi3717a_remove(struct spi_device *spi)
#else
static void hi3717a_remove(struct spi_device *spi)
#endif
{
	struct hi3717a *hi3717a = spi_get_drvdata(spi);
	struct hi3717a_priv *priv;
	int i;

	pr_info("avionics-hi3717a: Removing Device\n");

	atomic_set(&hi3717a->tx_enabled, 0);
	atomic_set(&hi3717a->rx_enabled, 0);


	for (i = 0; i < HI3717A_NUM_TX; i++) {
		if (hi3717a->tx[i]) {
			priv = avionics_device_priv(hi3717a->tx[i]);
			avionics_device_unregister(hi3717a->tx[i]);
			avionics_device_free(hi3717a->tx[i]);
			hi3717a->tx[i] = NULL;
		}
	}

	for (i = 0; i < HI3717A_NUM_RX; i++) {
		if (hi3717a->rx[i]) {
			priv = avionics_device_priv(hi3717a->rx[i]);
			if (priv) {
				if (priv->irq) {
					free_irq(priv->irq, priv);
				}
				cancel_delayed_work_sync(&priv->worker);
			}
			avionics_device_unregister(hi3717a->rx[i]);
			avionics_device_free(hi3717a->rx[i]);
			hi3717a->rx[i] = 0;
		}
	}

	if (hi3717a->reset_gpio > 0) {
		gpio_set_value(hi3717a->reset_gpio, 1);
		gpio_free(hi3717a->reset_gpio);
		hi3717a->reset_gpio = 0;
	}

	if (hi3717a->wq) {
		flush_scheduled_work();
		flush_workqueue(hi3717a->wq);
		destroy_workqueue(hi3717a->wq);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
	return 0;
#endif
}

static int hi3717a_probe(struct spi_device *spi)
{
	struct hi3717a *hi3717a;
	struct device *dev = &spi->dev;
	int err;

	pr_info("avionics-hi3717a: Adding Device\n");

	hi3717a = devm_kzalloc(dev, sizeof(*hi3717a), GFP_KERNEL);
	if (!hi3717a) {
		pr_err("avionics-hi3717a: Failed to allocate hi3717a memory\n");
		return -ENOMEM;
	}
	spi_set_drvdata(spi, hi3717a);
	mutex_init(&hi3717a->lock);
	atomic_set(&hi3717a->tx_enabled, 0);
	atomic_set(&hi3717a->rx_enabled, 0);

	err = hi3717a_get_config(spi);
	if (err) {
		pr_err("avionics-hi3717a: Failed to get system configuration"
		       " from dts file: %d\n",err);
		hi3717a_remove(spi);
		return err;
	}

	err = hi3717a_reset(spi);
	if (err) {
		pr_err("avionics-hi3717a: Failed to bring device"
		       " out of reset: %d\n",err);
		hi3717a_remove(spi);
		return err;
	}

	err = hi3717a_create_netdevs(spi);
	if (err) {
		pr_err("avionics-hi3717a: Failed to"
		       " register netdevs: %d\n", err);
		hi3717a_remove(spi);
		return err;
	}

	pr_info("avionics-hi3717a: Added Device\n");

	return 0;
}

static struct spi_driver hi3717a_spi_driver = {
	.driver = {
		.name = "hi3717a",
		.of_match_table = hi3717a_of_device_id,
	},
	.id_table = hi3717a_spi_device_id,
	.probe = hi3717a_probe,
	.remove = hi3717a_remove,
};
module_spi_driver(hi3717a_spi_driver);
