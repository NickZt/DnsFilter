package com.exampletest.dnsfilter.utils;


import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;

import com.exampletest.dnsfilter.tcpip.IPHeader;
import com.exampletest.dnsfilter.tcpip.TCPHeader;
import com.exampletest.dnsfilter.tcpip.UDPHeader;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class ProxyUtils {

    public static final boolean IS_DEBUG = true;

    public static boolean checkNet(Context context) {
        try {
            ConnectivityManager connectivity = (ConnectivityManager) context
                    .getSystemService(Context.CONNECTIVITY_SERVICE);
            if (connectivity != null) {
                NetworkInfo info = connectivity.getActiveNetworkInfo();
                if (info != null && info.isConnected()) {
                    if (info.getState() == NetworkInfo.State.CONNECTED) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    public static InetAddress ipIntToInet4Address(int ip) {
        byte[] ipAddress = new byte[4];
        writeInt(ipAddress, 0, ip);
        try {
            return Inet4Address.getByAddress(ipAddress);
        } catch (UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    public static String ipIntToString(int ip) {
        return String.format("%s.%s.%s.%s", (ip >> 24) & 0x00FF,
                (ip >> 16) & 0x00FF, (ip >> 8) & 0x00FF, ip & 0x00FF);
    }

    public static String ipBytesToString(byte[] ip) {
        return String.format("%s.%s.%s.%s", ip[0] & 0x00FF, ip[1] & 0x00FF, ip[2] & 0x00FF, ip[3] & 0x00FF);
    }

    public static int ipStringToInt(String ip) {
        String[] arrStrings = ip.split("\\.");
        int r = (Integer.parseInt(arrStrings[0]) << 24)
                | (Integer.parseInt(arrStrings[1]) << 16)
                | (Integer.parseInt(arrStrings[2]) << 8)
                | Integer.parseInt(arrStrings[3]);
        return r;
    }

    public static int readInt(byte[] data, int offset) {
        int r = ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        return r;
    }

    public static short readShort(byte[] data, int offset) {
        int r = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        return (short) r;
    }

    public static void writeInt(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >> 24);
        data[offset + 1] = (byte) (value >> 16);
        data[offset + 2] = (byte) (value >> 8);
        data[offset + 3] = (byte) (value);
    }

    public static void writeShort(byte[] data, int offset, short value) {
        data[offset] = (byte) (value >> 8);
        data[offset + 1] = (byte) (value);
    }

    // 网络字节顺序与主机字节顺序的Conversion

    public static short htons(short u) {
        int r = ((u & 0xFFFF) << 8) | ((u & 0xFFFF) >> 8);
        return (short) r;
    }

    public static short ntohs(short u) {
        int r = ((u & 0xFFFF) << 8) | ((u & 0xFFFF) >> 8);
        return (short) r;
    }

    public static int hton(int u) {
        int r = (u >> 24) & 0x000000FF;
        r |= (u >> 8) & 0x0000FF00;
        r |= (u << 8) & 0x00FF0000;
        r |= (u << 24) & 0xFF000000;
        return r;
    }

    public static int ntoh(int u) {
        int r = (u >> 24) & 0x000000FF;
        r |= (u >> 8) & 0x0000FF00;
        r |= (u << 8) & 0x00FF0000;
        r |= (u << 24) & 0xFF000000;
        return r;
    }

    // Calculate checksum
    public static short checksum(long sum, byte[] buf, int offset, int len) {
        sum += getsum(buf, offset, len);
        while ((sum >> 16) > 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (short) ~sum;
    }

    public static long getsum(byte[] buf, int offset, int len) {
        long sum = 0; /* assume 32 bit long, 16 bit short */
        while (len > 1) {
            sum += readShort(buf, offset) & 0xFFFF;
            offset += 2;
            len -= 2;
        }

        if (len > 0) /* take care of left over byte */ {
            sum += (buf[offset] & 0xFF) << 8;
        }
        return sum;
    }

    // Calculate the checksum of the IP packet
    public static boolean ComputeIPChecksum(IPHeader ipHeader) {
        short oldCrc = ipHeader.getCrc();
        ipHeader.setCrc((short) 0);// Calculate leading zero
        short newCrc = ProxyUtils.checksum(0, ipHeader.mData,
                ipHeader.mOffset, ipHeader.getHeaderLength());
        ipHeader.setCrc(newCrc);
        return oldCrc == newCrc;
    }

    // Calculate the checksum of TCP or UDP
    public static boolean ComputeTCPChecksum(IPHeader ipHeader, TCPHeader tcpHeader) {
        ComputeIPChecksum(ipHeader);//Calculate IP checksum
        int ipData_len = ipHeader.getTotalLength() - ipHeader.getHeaderLength();// IP data length
        if (ipData_len < 0)
            return false;
        // Calculate as pseudo header and
        long sum = getsum(ipHeader.mData, ipHeader.mOffset
                + IPHeader.offset_src_ip, 8);
        sum += ipHeader.getProtocol() & 0xFF;
        sum += ipData_len;

        short oldCrc = tcpHeader.getCrc();
        tcpHeader.setCrc((short) 0);// Calculation leading 0

        short newCrc = checksum(sum, tcpHeader.m_Data, tcpHeader.m_Offset, ipData_len);// Calculate checksum

        tcpHeader.setCrc(newCrc);
        return oldCrc == newCrc;
    }

    // Calculate the checksum of TCP or UDP
    public static boolean ComputeUDPChecksum(IPHeader ipHeader, UDPHeader udpHeader) {
        ComputeIPChecksum(ipHeader);//Calculate IP checksum
        int ipData_len = ipHeader.getTotalLength() - ipHeader.getHeaderLength();// IP data length
        if (ipData_len < 0)
            return false;
        // Calculate as pseudo header and
        long sum = getsum(ipHeader.mData, ipHeader.mOffset
                + IPHeader.offset_src_ip, 8);
        sum += ipHeader.getProtocol() & 0xFF;
        sum += ipData_len;

        short oldCrc = udpHeader.getCrc();
        udpHeader.setCrc((short) 0);// Calculation leading 0

        short newCrc = checksum(sum, udpHeader.m_Data, udpHeader.m_Offset, ipData_len);// Calculate checksum

        udpHeader.setCrc(newCrc);
        return oldCrc == newCrc;
    }

    private final static int FAKE_NETWORK_MASK = ProxyUtils.ipStringToInt("255.255.0.0");
    //    For DNS replace
    private final static int FAKE_NETWORK_IP = ProxyUtils.ipStringToInt("10.231.0.0");

    public static boolean isFakeIP(int ip) {
        return (ip & FAKE_NETWORK_MASK) == FAKE_NETWORK_IP;
    }

    public static int fakeIP(int hashIP) {
        return FAKE_NETWORK_IP | (hashIP & 0x0000FFFF);
    }

    public static String fakeNetWorkIP() {
        return ipIntToString(FAKE_NETWORK_IP);
    }
}