package com.nitrokey.wallet

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.*
import android.util.Log

/**
 * Android 原生 USB CCID 驱动插件
 * 用于在无系统 PC/SC 守护进程的 Android 系统上直连 Nitrokey HSM 2
 */
class UsbCcidPlugin(private val context: Context) {
    companion object {
        private const val TAG = "UsbCcidPlugin"
        private const val ACTION_USB_PERMISSION = "com.nitrokey.wallet.USB_PERMISSION"
        private const val CCID_INTERFACE_CLASS = 0x0B
    }

    private val usbManager: UsbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
    private var usbDevice: UsbDevice? = null
    private var usbConnection: UsbDeviceConnection? = null
    private var endpointIn: UsbEndpoint? = null
    private var endpointOut: UsbEndpoint? = null
    private var sequenceNumber: Byte = 0

    // 监听 USB 授权结果
    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (ACTION_USB_PERMISSION == intent.action) {
                synchronized(this) {
                    val device: UsbDevice? = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        device?.let { setupConnection(it) }
                    } else {
                        Log.e(TAG, "用户拒绝了 USB 设备授权")
                    }
                }
            }
        }
    }

    init {
        val filter = IntentFilter(ACTION_USB_PERMISSION)
        context.registerReceiver(usbReceiver, filter)
    }

    /**
     * 扫描插入的 Nitrokey HSM 2 或标准 CCID 设备
     */
    fun findCcidDevice(): UsbDevice? {
        val deviceList = usbManager.deviceList
        for ((_, device) in deviceList) {
            for (i in 0 until device.interfaceCount) {
                val iface = device.getInterface(i)
                if (iface.interfaceClass == CCID_INTERFACE_CLASS) {
                    return device
                }
            }
        }
        return null
    }

    /**
     * 请求设备权限并打开连接
     */
    fun requestConnect(onReady: (Boolean) -> Unit) {
        val device = findCcidDevice()
        if (device == null) {
            onReady(false)
            return
        }

        usbDevice = device
        if (usbManager.hasPermission(device)) {
            val success = setupConnection(device)
            onReady(success)
        } else {
            val permissionIntent = PendingIntent.getBroadcast(
                context,
                0,
                Intent(ACTION_USB_PERMISSION),
                PendingIntent.FLAG_IMMUTABLE
            )
            usbManager.requestPermission(device, permissionIntent)
        }
    }

    private fun setupConnection(device: UsbDevice): Boolean {
        var ccidIface: UsbInterface? = null
        for (i in 0 until device.interfaceCount) {
            val iface = device.getInterface(i)
            if (iface.interfaceClass == CCID_INTERFACE_CLASS) {
                ccidIface = iface
                break
            }
        }
        if (ccidIface == null) return false

        for (i in 0 until ccidIface.endpointCount) {
            val ep = ccidIface.getEndpoint(i)
            if (ep.type == UsbConstants.USB_ENDPOINT_XFER_BULK) {
                if (ep.direction == UsbConstants.USB_DIR_IN) {
                    endpointIn = ep
                } else {
                    endpointOut = ep
                }
            }
        }

        val conn = usbManager.openDevice(device) ?: return false
        if (!conn.claimInterface(ccidIface, true)) {
            conn.close()
            return false
        }

        usbConnection = conn
        Log.i(TAG, "Nitrokey HSM 2 CCID 接口已成功声明并锁定")
        return true
    }

    /**
     * 发送 APDU 并获取应答 (暴露给 Rust JNI 调用)
     */
    fun transmitApdu(apdu: ByteArray): ByteArray {
        val conn = usbConnection ?: throw IllegalStateException("USB 未连接")
        val outEp = endpointOut ?: throw IllegalStateException("找不到 Bulk-OUT 端点")
        val inEp = endpointIn ?: throw IllegalStateException("找不到 Bulk-IN 端点")

        sequenceNumber = ((sequenceNumber + 1) % 256).toByte()

        // 组装 CCID PC_to_RDR_XfrBlock (10 字节头 + APDU)
        val ccidHeader = ByteArray(10)
        ccidHeader[0] = 0x6F.toByte() // PC_to_RDR_XfrBlock
        ccidHeader[1] = (apdu.size and 0xFF).toByte()
        ccidHeader[2] = ((apdu.size shr 8) and 0xFF).toByte()
        ccidHeader[3] = ((apdu.size shr 16) and 0xFF).toByte()
        ccidHeader[4] = ((apdu.size shr 24) and 0xFF).toByte()
        ccidHeader[5] = 0x00 // Slot 0
        ccidHeader[6] = sequenceNumber
        ccidHeader[7] = 0x00 // BWI
        ccidHeader[8] = 0x00
        ccidHeader[9] = 0x00

        val sendBuffer = ccidHeader + apdu
        val sent = conn.bulkTransfer(outEp, sendBuffer, sendBuffer.size, 3000)
        if (sent < 0) throw RuntimeException("USB 发送失败")

        // 接收 CCID RDR_to_PC_DataBlock 响应
        val recvBuffer = ByteArray(2048)
        val readLen = conn.bulkTransfer(inEp, recvBuffer, recvBuffer.size, 5000)
        if (readLen < 10) throw RuntimeException("CCID 响应长度不足")

        val apduLen = (recvBuffer[1].toInt() and 0xFF) or ((recvBuffer[2].toInt() and 0xFF) shl 8)
        return recvBuffer.copyOfRange(10, 10 + apduLen)
    }

    fun release() {
        try {
            context.unregisterReceiver(usbReceiver)
        } catch (_: Exception) {}
        usbConnection?.close()
        usbConnection = null
    }
}
