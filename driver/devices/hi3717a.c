/*
 * Copyright (C), 2019 CCX Technologies
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

#include "avionics.h"
#include "avionics-device.h"

MODULE_DESCRIPTION("HOLT Hi-3717A ARINC-717 Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.0");

#define HI3717A_MTU	(32*sizeof(__u32)) /* 32 word FIFO, includes word count */

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


#define HI3717A_FIFO_FULL	0x10
#define HI3717A_FIFO_HALF	0x08
#define HI3717A_FIFO_EMPTY	0x04
#define HI3717A_FIFO_OVF	0x02

#define HI3717A_NUM_TX	1
#define HI3717A_NUM_RX	1

struct hi3717a {
	struct net_device *rx[HI3717A_NUM_RX];
	struct net_device *tx[HI3717A_NUM_TX];
	int reset_gpio;
	int irq;
	struct mutex lock;
};

struct hi3717a_priv {
	struct net_device *dev;
	struct spi_device *spi;
	struct sk_buff_head skbq;
	int tx_index;
	int rx_index;
	struct mutex *lock;
	struct workqueue_struct *wq;
	struct work_struct worker;
	int irq;
};

static ssize_t hi3717a_get_ctrl(struct hi3717a_priv *priv, __u8 opcode)
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

	status = hi3717a_get_ctrl(priv, rd_opcode);
	if (status < 0) {
		pr_err("avionics-hi3717a: Failed to read ctrl 0x%x: %d\n",
		       rd_opcode, status);
		mutex_unlock(priv->lock);
		return -ENODEV;
	}

	if ((status&mask) == (value&mask)) {
		return;
	}

	wr_cmd[0] = wr_opcode;

	wr_cmd[1] = (status&(~mask)) | (value&mask);
	err = spi_write(priv->spi, wr_cmd, sizeof(wr_cmd));
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to set ctrl 0x%x\n", wr_cmd);
		mutex_unlock(priv->lock);
		return err;
	}

	status = hi3717a_get_ctrl(priv, rd_opcode);
	if (status < 0) {
		pr_err("avionics-hi3717a: Failed to read ctrl 0x%x: %d\n",
		       rd_opcode, status);
		mutex_unlock(priv->lock);
		return -ENODEV;
	}

	if ((status&mask) != (value&mask)) {
		pr_err("avionics-hi3717a: Failed to set"
		       " ctrl 0x%x to 0x%x & 0x%x : 0x%x\n",
		       wr_cmd_value, mask, status);
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
		pr_warn("avionics-hi3717a: speed must be 1536, 3072,"
			" 6144, 12288, 24576, 49152, or 98304 Hz\n");
		return -EINVAL;
	}

	ctrl0 = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_CTRL0);
	if (ctrl0 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL0\n");
		return ctrl0;
	}

	if ((ctrl0&0x78) == value) {
		return 0;
	}

	pr_warn("avionics-hi3717a: resetting device to change speed\n");

	ctrl1 = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_CTRL1);
	if (ctrl1 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL1\n");
		return ctrl1;
	}

	fspin = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_FSPIN);
	if (fspin < 0) {
		pr_err("avionics-hi3717a: Failed to read FSPIN\n");
		return fspin;
	}

	wrdcnt = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_WRDCNT);
	if (wrdcnt < 0) {
		pr_err("avionics-hi3717a: Failed to read WRDCNT\n");
		return wrdcnt;
	}

	gpio_set_value(hi3717a->reset_gpio, 0);
	usleep_range(10, 100);
	gpio_set_value(hi3717a->reset_gpio, 1);

	err = hi3717a_set_cntrl(priv, wrdcnt, 0xff,
			  HI3717A_OPCODE_WR_WRDCNT, HI3717A_OPCODE_RD_WRDCNT);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to reset WRDCNT\n");
		return err;
	}

	err = hi3717a_set_cntrl(priv, fspin, 0xff,
			  HI3717A_OPCODE_WR_FSPIN, HI3717A_OPCODE_RD_FSPIN);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to reset FSPIN\n");
		return err;
	}

	err = hi3717a_set_cntrl(priv, ctrl1, 0xff,
			  HI3717A_OPCODE_WR_CTRL1, HI3717A_OPCODE_RD_CTRL1);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to reset CTRL1\n");
		return err;
	}

	err = hi3717a_set_cntrl(priv, (ctrl0&(~0x78)) | (value&0x78) , 0xff,
			  HI3717A_OPCODE_WR_CTRL0, HI3717A_OPCODE_RD_CTRL0);
	if (err < 0) {
		pr_err("avionics-hi3717a: Failed to set CTRL0\n");
		return err;
	}

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
		pr_err("avionics-hi3717a: Failed to get rate: %d\n", status);
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
	__u8 rd_priority, rd_filters;
	ssize_t cntrl0, cntrl1;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
	}

	ctrl0 = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_CTRL0);
	if (ctrl0 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL0\n");
	}

	ctrl1 = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_CTRL1);
	if (ctrl1 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL1\n");
	}

	config->flags = (ctrl0&0x01)|(cntrl1&0x06);

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
	ssize_t status;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
	}

	ctrl0 = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_CTRL0);
	if (ctrl0 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL0\n");
	}

	ctrl1 = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_CTRL1);
	if (ctrl1 < 0) {
		pr_err("avionics-hi3717a: Failed to read CTRL1\n");
	}

	config->flags = (ctrl0&0x06)|(cntrl1&0x01);

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
		pr_err("avionics-hi3717a: MTU must be %d.\n", HI3717A_MTU);
		return -EINVAL;
	}

	return 0;
}

static int hi3717a_tx_open(struct net_device *dev)
{
	pr_warn("avionics-hi3717a: Enabling Driver\n");
	netif_wake_queue(dev);

	return 0;
}

static int hi3717a_tx_stop(struct net_device *dev)
{
	struct hi3717a_priv *priv;
	int err;

	pr_warn("avionics-hi3717a: Disabling Driver\n");

	netif_stop_queue(dev);

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return -EINVAL;
	}

	skb_queue_purge(&priv->skbq);
	flush_workqueue(priv->wq);

	return 0;
}

static void hi3717a_rx_worker(struct work_struct *work)
{
	struct net_device *dev;
	struct net_device_stats *stats;
	struct hi3717a_priv *priv;
	struct sk_buff *skb;
	__u8 rd_cmd, data[HI3717A_MTU];
	ssize_t status;
	int err, i, cnt;

	priv = container_of(work, struct hi3717a_priv, worker);
	dev = priv->dev;
	stats = &dev->stats;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return;
	}

	mutex_lock(priv->lock);

	status = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_RXFSTAT);
	if (status < 0) {
		pr_err("avionics-hi3717a: Failed to read status\n");
		mutex_unlock(priv->lock);
		return;
	}

	if (status & HI3717A_FIFO_OVF) {
		stats->rx_errors++;
		stats->rx_fifo_errors++;
	}

	cnt = 0;
	rd_cmd = HI3717A_OPCODE_RD_RXFIFO;
	if (!(status & HI3717A_FIFO_EMPTY)) {
		for (i = 0; i < HI3717A_MTU; i += sizeof(__u32)) {
			err = spi_write_then_read(priv->spi, &rd_cmd,
						  sizeof(rd_cmd),
						  &data[cnt],
						  sizeof(__u32));
			if (unlikely(err)) {
				pr_err("avionics-hi3717a: Failed to"
				       " read from fifo\n");
				mutex_unlock(priv->lock);
				return;
			}

			cnt += sizeof(__u32);

			status = spi_w8r8(priv->spi, status_cmd);
			status = hi3717a_get_ctrl(priv,
						  HI3717A_OPCODE_RD_RXFSTAT);
			if (unlikely(status < 0)) {
				pr_err("avionics-hi3717a: Failed to"
				       " read status\n");
				mutex_unlock(priv->lock);
				return;
			}

			if(status & HI3717A_FIFO_EMPTY) {
				break;
			}
		}

		if (cnt) {
			skb = avionics_device_alloc_skb(dev, cnt);
			if (unlikely(!skb)) {
				pr_err("avionics-lb: Failed to"
				       " allocate RX buffer\n");
				mutex_unlock(priv->lock);
				return;
			}

			skb_copy_to_linear_data(skb, data, cnt);

			stats->rx_packets++;
			stats->rx_bytes += skb->len;

			netif_rx_ni(skb);
		}
	}

	mutex_unlock(priv->lock);

}

static irqreturn_t hi3717a_rx_irq(int irq, void *data)
{
	struct hi3717a_priv *priv = data;

	queue_work(priv->wq, &priv->worker);
	return IRQ_HANDLED;
}

static void hi3717a_tx_worker(struct work_struct *work)
{
	struct net_device *dev;
	struct net_device_stats *stats;
	struct hi3717a_priv *priv;
	struct sk_buff *skb;
	__u8 rd_cmd, wr_cmd[3], send_cmd;
	ssize_t status;
	int err, i;

	priv = container_of(work, struct hi3717a_priv, worker);
	dev = priv->dev;
	stats = &dev->stats;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3717a: Failed to get private data\n");
		return;
	}

	skb = skb_dequeue(&priv->skbq);
	if (!skb) {
		return;
	}

	mutex_lock(priv->lock);

	status = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_TXFSTAT);
	if (status < 0) {
		pr_err("avionics-hi3717a: Failed to read status\n");
		mutex_unlock(priv->lock);
		return;
	}

	if (status & 0x80) {
		/* TODO: Come up with a better dropping algo. */
		kfree_skb(skb);
		stats->tx_dropped++;
		mutex_unlock(priv->lock);
		return;
	}

	wr_cmd[0] = HI3717A_OPCODE_WR_TXFIFO;
	for (i = 0; i < skb->len; i = i + sizeof(__u16)) {
		memcpy(&wr_cmd[1], &skb->data[i], sizeof(__u16));
		err = spi_write(priv->spi, &wr_cmd, sizeof(wr_cmd));
		if (err < 0) {
			pr_err("avionics-hi3717a: Failed to load fifo\n");
			mutex_unlock(priv->lock);
			return;
		}
	}

	mutex_unlock(priv->lock);

	stats->tx_packets++;
	stats->tx_bytes += skb->len;

	consume_skb(skb);
}

static netdev_tx_t hi3717a_tx_start_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	struct hi3717a_priv *priv;

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

	skb_queue_tail(&priv->skbq, skb);
	queue_work(priv->wq, &priv->worker);

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
	int err, i;

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
	__u8 opcode;
	ssize_t status;
	int err;

	gpio_set_value(hi3717a->reset_gpio, 0);
	usleep_range(10, 100);
	gpio_set_value(hi3717a->reset_gpio, 1);

	status = hi3717a_get_ctrl(priv, HI3717A_OPCODE_RD_TXFSTAT);
	if (status != 0x01) {
		pr_err("avionics-hi3717a: TX FIFO is not cleared: %x\n",
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
	.flags = 0,
};

static int hi3717a_create_netdevs(struct spi_device *spi)
{
	struct hi3717a *hi3717a = spi_get_drvdata(spi);
	struct hi3717a_priv *priv;
	int i, err;

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
		priv->tx_index = i;
		priv->rx_index = -1;
		skb_queue_head_init(&priv->skbq);
		priv->wq = alloc_workqueue("%s", WQ_FREEZABLE | WQ_MEM_RECLAIM,
					   0, hi3717a->tx[i]->name);
		if (!priv->wq) {
			pr_err("avionics-hi3717a: Failed to allocate"
			       " tx work-queue %d\n", i);
			return -ENOMEM;
		}

		INIT_WORK(&priv->worker, hi3717a_tx_worker);

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
		priv->tx_index = -1;
		priv->rx_index = i;
		skb_queue_head_init(&priv->skbq);
		priv->wq = alloc_workqueue("%s", WQ_FREEZABLE | WQ_MEM_RECLAIM,
					   0, hi3717a->rx[i]->name);
		if (!priv->wq) {
			pr_err("avionics-hi3717a: Failed to allocate"
			       " rx work-queue %d\n", i);
			return -ENOMEM;
		}

		INIT_WORK(&priv->worker, hi3717a_rx_worker);

		err = request_irq(hi3717a->irq[i], hi3717a_rx_irq,
				  IRQF_TRIGGER_RISING | IRQF_ONESHOT,
				  hi3717a->rx[i]->name, priv);
		if (err) {
			pr_err("avionics-hi3717a: Failed to register"
			       " RX %d irq %d\n", i, hi3717a->irq[i]);
			return -EINVAL;
		}
		priv->irq = hi3717a->irq[i];

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

static int hi3717a_remove(struct spi_device *spi)
{
	struct hi3717a *hi3717a = spi_get_drvdata(spi);
	struct hi3717a_priv *priv;
	int i;

	pr_info("avionics-hi3717a: Removing Device\n");

	for (i = 0; i < HI3717A_NUM_TX; i++) {
		if (hi3717a->tx[i]) {
			priv = avionics_device_priv(hi3717a->tx[i]);
			if (priv) {
				skb_queue_purge(&priv->skbq);
				destroy_workqueue(priv->wq);
			}
			avionics_device_unregister(hi3717a->tx[i]);
			avionics_device_free(hi3717a->tx[i]);
			hi3717a->tx[i] = NULL;
		}
	}

	for (i = 0; i < HI3717A_NUM_RX; i++) {
		if (hi3717a->rx[i]) {
			priv = avionics_device_priv(hi3717a->rx[i]);
			if (priv) {
				skb_queue_purge(&priv->skbq);
				destroy_workqueue(priv->wq);
				if (priv->irq) {
					free_irq(priv->irq, priv);
				}
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

	return 0;
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
