package com.exampletest.dnsfilter.dns;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.ParcelFileDescriptor;
import android.util.Log;


import com.exampletest.dnsfilter.MainActivity;
import com.exampletest.dnsfilter.R;
import com.exampletest.dnsfilter.dnsheader.DnsPacket;
import com.exampletest.dnsfilter.tcpip.IPHeader;
import com.exampletest.dnsfilter.tcpip.TCPHeader;
import com.exampletest.dnsfilter.tcpip.UDPHeader;
import com.exampletest.dnsfilter.utils.ProxyUtils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.exampletest.dnsfilter.MainActivity.REQUEST_CODE;
import static com.exampletest.dnsfilter.utils.ProxyUtils.IS_DEBUG;

public class LocalVpnService extends VpnService implements Runnable {

    private String mDOHUrl;

    public static LocalVpnService getInstance() {
        return Instance;
    }

    public static Intent getService() {
        return Service;
    }

    public static void setService(Intent service) {
        LocalVpnService.Service = service;
    }

    private static Intent Service = null;
    private static LocalVpnService Instance;
    public static String ConfigUrl;

    private static int ID;
    private static int LOCAL_IP;
    private static ConcurrentHashMap<onStatusChangedListener, Object> sOnStatusChangedListeners = new ConcurrentHashMap<onStatusChangedListener, Object>();

    private Thread mVPNThread;
    private ParcelFileDescriptor mVPNInterface;
    private TcpProxyServer mTCPProxyServer;
    private DnsProxy mDnsProxy;
    private FileOutputStream mVPNOutputStream;

    private byte[] mPacket;
    private IPHeader mIPHeader;
    private TCPHeader mTCPHeader;
    private UDPHeader mUDPHeader;
    private ByteBuffer mDNSBuffer;
    private Handler mHandler;
    private long mSentBytes;
    private long mReceivedBytes;


//    private ProxyConfigLoader mProxyCofigLoader;

    public LocalVpnService() {
        ID++;
        mHandler = new Handler();
        mPacket = new byte[20000];
        mIPHeader = new IPHeader(mPacket, 0);
        mTCPHeader = new TCPHeader(mPacket, 20);
        mUDPHeader = new UDPHeader(mPacket, 20);
        mDNSBuffer = ((ByteBuffer) ByteBuffer.wrap(mPacket).position(28)).slice();
        Instance = this;

        System.out.printf("New VPNService(%d)\n", ID);

//        mProxyCofigLoader = ProxyConfigLoader.getsInstance();
//        mProxyCofigLoader.setOnProxyConfigLoadListener(this);

    }

    @Override
    public void onCreate() {
        System.out.printf("VPNService(%s) created.\n", ID);
        super.onCreate();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
//todo clean this
        Instance = this;
        Service = intent;
        mDOHUrl = intent.getStringExtra("PROXY_URL");
        mVPNThread = new Thread(this, "VPNServiceThread");
        mVPNThread.start();
        return super.onStartCommand(intent, flags, startId);
    }


    public static void addOnStatusChangedListener(onStatusChangedListener listener) {
        if (!sOnStatusChangedListeners.containsKey(listener)) {
            sOnStatusChangedListeners.put(listener, 1);
        }
    }

    public static void removeOnStatusChangedListener(onStatusChangedListener listener) {
        if (sOnStatusChangedListeners.containsKey(listener)) {
            sOnStatusChangedListeners.remove(listener);
        }
    }

    private void onConnectionError() {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                for (Map.Entry<onStatusChangedListener, Object> entry : sOnStatusChangedListeners.entrySet()) {
                    entry.getKey().onConnectionError();
                }
            }
        });
    }

    private void onConnectionChanged(final boolean isConn) {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                for (Map.Entry<onStatusChangedListener, Object> entry : sOnStatusChangedListeners.entrySet()) {
                    entry.getKey().onConnectionChanged(isConn);
                }
            }
        });
    }

    private void onStatusChanged(final String status, final boolean isRunning) {
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                for (Map.Entry<onStatusChangedListener, Object> entry : sOnStatusChangedListeners.entrySet()) {
                    entry.getKey().onStatusChanged(status, isRunning);
                }
            }
        });
    }

    public void writeLog(final String format, Object... args) {
        final String logString = String.format(format, args);
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                for (Map.Entry<onStatusChangedListener, Object> entry : sOnStatusChangedListeners.entrySet()) {
                    entry.getKey().onLogReceived(logString);
                }
            }
        });
    }

    public void sendUDPPacket(IPHeader ipHeader, UDPHeader udpHeader) {
        try {
            ProxyUtils.ComputeUDPChecksum(ipHeader, udpHeader);
            this.mVPNOutputStream.write(ipHeader.mData, ipHeader.mOffset, ipHeader.getTotalLength());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public synchronized void run() {
        try {

            mTCPProxyServer = new TcpProxyServer(0);
            mTCPProxyServer.start();
            writeLog("LocalTcpServer started.");

            mDnsProxy = new DnsProxy();
            mDnsProxy.start();
            writeLog("LocalDnsProxy started.");

            runVPN();

        } catch (InterruptedException e) {
            Log.e(" TODEL ", e.getMessage());
            onConnectionError();
        } catch (Exception e) {
            e.printStackTrace();
            writeLog("Fatal error: %s", e.toString());
            onConnectionError();
        } finally {
            writeLog("SmartProxy terminated.");
            dispose();
        }
    }

    private void runVPN() throws Exception {
        this.mVPNInterface = establishVPN();
        this.mVPNOutputStream = new FileOutputStream(mVPNInterface.getFileDescriptor());
        FileInputStream in = new FileInputStream(mVPNInterface.getFileDescriptor());

        int size;
        while ((size = in.read(mPacket)) != -1) {
            if (mDnsProxy.Stopped || mTCPProxyServer.Stopped) {
                in.close();
                throw new Exception("LocalServer stopped.");
            }
            if (size == 0) {
                Thread.sleep(100);
            } else {
                onIPPacketReceived(mIPHeader, size);
            }

        }


        in.close();
        disconnectVPN();
    }

    void onIPPacketReceived(IPHeader ipHeader, int size) throws IOException {
        switch (ipHeader.getProtocol()) {
            case IPHeader.TCP:
                TCPHeader tcpHeader = mTCPHeader;
                tcpHeader.m_Offset = ipHeader.getHeaderLength();
                if (ipHeader.getSourceIP() == LOCAL_IP) {
                    if (tcpHeader.getSourcePort() == mTCPProxyServer.Port) {// Получать данные локального TCP-сервера
                        NatSession session = NatSessionManager.getSession(tcpHeader.getDestinationPort());
                        if (session != null) {
                            ipHeader.setSourceIP(ipHeader.getDestinationIP());
                            tcpHeader.setSourcePort(session.RemotePort);
                            ipHeader.setDestinationIP(LOCAL_IP);

                            ProxyUtils.ComputeTCPChecksum(ipHeader, tcpHeader);
                            mVPNOutputStream.write(ipHeader.mData, ipHeader.mOffset, size);
                            mReceivedBytes += size;
                        } else {
                            System.out.printf("NoSession: %s %s\n", ipHeader.toString(), tcpHeader.toString());
                        }
                    } else {

                        // Добавить сопоставление портов
                        int portKey = tcpHeader.getSourcePort();
                        NatSession session = NatSessionManager.getSession(portKey);
                        if (session == null || session.RemoteIP != ipHeader.getDestinationIP() || session.RemotePort != tcpHeader.getDestinationPort()) {
                            session = NatSessionManager.createSession(portKey, ipHeader.getDestinationIP(), tcpHeader.getDestinationPort());
                        }

                        session.LastNanoTime = System.nanoTime();
                        session.PacketSent++;//Обратите внимание на порядок

                        int tcpDataSize = ipHeader.getDataLength() - tcpHeader.getHeaderLength();
                        if (session.PacketSent == 2 && tcpDataSize == 0) {
                            return;//Второй пакет ACK подтверждения TCP отбрасывается. Поскольку клиент также передает ACK при отправке данных, он может проанализировать информацию HOST до того, как сервер примет.
                        }

                        //分析数据，找到host
                        if (session.BytesSent == 0 && tcpDataSize > 10) {
                            int dataOffset = tcpHeader.m_Offset + tcpHeader.getHeaderLength();
                            String host = HttpHostHeaderParser.parseHost(tcpHeader.m_Data, dataOffset, tcpDataSize);
                            if (host != null) {
                                session.RemoteHost = host;
                            }
                        }

                        // Forward  给本地TCP服务器
                        ipHeader.setSourceIP(ipHeader.getDestinationIP());
                        ipHeader.setDestinationIP(LOCAL_IP);
                        tcpHeader.setDestinationPort(mTCPProxyServer.Port);

                        ProxyUtils.ComputeTCPChecksum(ipHeader, tcpHeader);
                        mVPNOutputStream.write(ipHeader.mData, ipHeader.mOffset, size);
                        session.BytesSent += tcpDataSize;//Обратите внимание на порядок
                        mSentBytes += size;
                    }
                }
                break;
            case IPHeader.UDP:
                //  Forward DNS packets：
                UDPHeader udpHeader = mUDPHeader;
                udpHeader.m_Offset = ipHeader.getHeaderLength();
                if (ipHeader.getSourceIP() == LOCAL_IP && udpHeader.getDestinationPort() == 53) {
                    mDNSBuffer.clear();
                    mDNSBuffer.limit(ipHeader.getDataLength() - 8);
                    DnsPacket dnsPacket = DnsPacket.FromBytes(mDNSBuffer);
                    if (dnsPacket != null && dnsPacket.Header.QuestionCount > 0) {
                        mDnsProxy.onDnsRequestReceived(ipHeader, udpHeader, dnsPacket);
                    }
                }
                break;
        }
    }


    private ParcelFileDescriptor establishVPN() throws Exception {
        Builder builder = new Builder();

        builder.setMtu(3000);
        if (IS_DEBUG)
            System.out.printf("setMtu: %d\n", 3000);
        LOCAL_IP = ProxyUtils.ipStringToInt("10.0.2.15");

        builder.addAddress("10.0.2.15", 24);

        builder.addDnsServer("8.8.8.8");

        builder.addRoute("8.8.8.8", 32);
        if (IS_DEBUG)
            System.out.printf("addDefaultRoute: 8.8.8.8/0\n");

        Class<?> SystemProperties = Class.forName("android.os.SystemProperties");
        Method method = SystemProperties.getMethod("get", new Class[]{String.class});
        ArrayList<String> servers = new ArrayList<String>();
        for (String name : new String[]{"net.dns1", "net.dns2", "net.dns3", "net.dns4",}) {
            String value = (String) method.invoke(null, name);
            if (value != null && !"".equals(value) && !servers.contains(value)) {
                servers.add(value);
                builder.addRoute(value, 32);
                if (IS_DEBUG)
                    System.out.printf("%s=%s\n", name, value);
            }
        }

        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, REQUEST_CODE, intent, 0);
        builder.setConfigureIntent(pendingIntent);
        ParcelFileDescriptor pfdDescriptor = builder.establish();
        onConnectionChanged(true);
        return pfdDescriptor;
    }

    public void disconnectVPN() {
        try {
            if (mVPNInterface != null) {
                mVPNInterface.close();
                mVPNInterface = null;
            }
        } catch (Exception e) {
            // ignore
        }
        onStatusChanged( getString(R.string.vpn_disconnected_status), false);
        onConnectionChanged(false);
        this.mVPNOutputStream = null;
    }
    // proxyUrl
//    private String[] downloadDOHConfig(String url) throws Exception {
//        try {
//            OkHttpClient okHttpClient = new OkHttpClient();
//            Request request = new Request.Builder().url(url).get().build();
//            Call call = okHttpClient.newCall(request);
//            Response response = call.execute();
//
//            String line = response.body().string();
//            return line.split("\n");
//        } catch (Exception e) {
//
//            String error = e.getLocalizedMessage();
//            throw new Exception(String.format("Download config file from %s failed. %s", url, error));
//        }
//    }
    private synchronized void dispose() {
        // disconnect VPN
        disconnectVPN();

        // stop TcpServer
        if (mTCPProxyServer != null) {
            mTCPProxyServer.stop();
            mTCPProxyServer = null;
            writeLog("LocalTcpServer stopped.");
        }

        // stop DNS解析器
        if (mDnsProxy != null) {
            mDnsProxy.stop();
            mDnsProxy = null;
            writeLog("LocalDnsProxy stopped.");
        }

        stopSelf();
        System.exit(0);
    }

    @Override
    public void onDestroy() {
        System.out.printf("VPNService(%s) destoried.\n", ID);
        if (mVPNThread != null) {
            mVPNThread.interrupt();
        }
    }

    public interface onStatusChangedListener {
        public void onStatusChanged(String status, Boolean isRunning);

        public void onLogReceived(String logString);

        public void onConnectionChanged(boolean isConn);

        public void onConnectionError();
    }

}