package com.exampletest.dnsfilter.dns;

import android.util.Log;
import android.util.SparseArray;
//https://dns.google/resolve?name=facebook.com&type=A

import com.exampletest.dnsfilter.dnsheader.DnsPacket;
import com.exampletest.dnsfilter.dnsheader.Question;
import com.exampletest.dnsfilter.dnsheader.Resource;
import com.exampletest.dnsfilter.dnsheader.ResourcePointer;
import com.exampletest.dnsfilter.tcpip.IPHeader;
import com.exampletest.dnsfilter.tcpip.UDPHeader;
import com.exampletest.dnsfilter.utils.ProxyUtils;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

import static com.exampletest.dnsfilter.utils.ProxyUtils.IS_DEBUG;


public class DnsProxy implements Runnable {

    private class QueryState {
        public short ClientQueryID;
        public long QueryNanoTime;
        public int ClientIP;
        public short ClientPort;
        public int RemoteIP;
        public short RemotePort;
    }

    public boolean Stopped;
    private static final ConcurrentHashMap<Integer, String> IPDomainMaps = new ConcurrentHashMap<Integer, String>();
    private static final ConcurrentHashMap<String, Integer> DomainIPMaps = new ConcurrentHashMap<String, Integer>();
    private DatagramSocket mClient;
    private short mQueryID;
    private final SparseArray<QueryState> mQueryArray;

    public DnsProxy() throws IOException {
        mQueryArray = new SparseArray<QueryState>();
        mClient = new DatagramSocket(0);
    }

    public static String reverseLookup(int ip) {
        return IPDomainMaps.get(ip);
    }

    public void start() {
        Thread m_ReceivedThread = new Thread(this);
        m_ReceivedThread.setName("DnsProxyThread");
        m_ReceivedThread.start();
    }

    public void stop() {
        Stopped = true;
        if (mClient != null) {
            mClient.close();
            mClient = null;
        }
    }

    @Override
    public void run() {
        try {
            byte[] RECEIVE_BUFFER = new byte[2000];
            IPHeader ipHeader = new IPHeader(RECEIVE_BUFFER, 0);
            ipHeader.Default();
            UDPHeader udpHeader = new UDPHeader(RECEIVE_BUFFER, 20);

            ByteBuffer dnsBuffer = ByteBuffer.wrap(RECEIVE_BUFFER);
            dnsBuffer.position(28);
            dnsBuffer = dnsBuffer.slice();

            DatagramPacket packet = new DatagramPacket(RECEIVE_BUFFER, 28, RECEIVE_BUFFER.length - 28);

            while (mClient != null && !mClient.isClosed()) {

                packet.setLength(RECEIVE_BUFFER.length - 28);
                mClient.receive(packet);

                dnsBuffer.clear();
                dnsBuffer.limit(packet.getLength());
                try {
                    DnsPacket dnsPacket = DnsPacket.FromBytes(dnsBuffer);
                    if (dnsPacket != null) {
                        OnDnsResponseReceived(ipHeader, udpHeader, dnsPacket);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    LocalVpnService.getInstance().writeLog("Parse dns error: %s", e);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
           Log.d(" TODEL ","DnsResolver Thread Exited.");
            this.stop();
        }
    }

    private int getFirstIP(DnsPacket dnsPacket) {
        for (int i = 0; i < dnsPacket.Header.ResourceCount; i++) {
            Resource resource = dnsPacket.Resources[i];
            if (resource.Type == 1) {
                int ip = ProxyUtils.readInt(resource.Data, 0);
                return ip;
            }
        }
        return 0;
    }

    private void tamperedDnsResponse(byte[] rawPacket, DnsPacket dnsPacket, int newIP) {
        Question question = dnsPacket.Questions[0];

        dnsPacket.Header.setResourceCount((short) 1);
        dnsPacket.Header.setAResourceCount((short) 0);
        dnsPacket.Header.setEResourceCount((short) 0);

        ResourcePointer rPointer = new ResourcePointer(rawPacket, question.Offset() + question.Length());
        rPointer.setDomain((short) 0xC00C);
        rPointer.setType(question.Type);
        rPointer.setClass(question.Class);
//        rPointer.setTTL(ProxyConfigLoader.getsInstance().getDnsTTL());
        rPointer.setDataLength((short) 4);
        rPointer.setIP(newIP);

        dnsPacket.Size = 12 + question.Length() + 16;
    }

    private int getOrCreateFakeIP(String domainString) {
        Log.d("REPLACE>", "getOrCreateFakeIP() called with: domainString = [" + domainString + "]");
        //todo replace this to http ask
        Integer fakeIP = DomainIPMaps.get(domainString);
        if (fakeIP == null) {
            int hashIP = domainString.hashCode();
            do {
                fakeIP = ProxyUtils.fakeIP(hashIP);
                hashIP++;
            } while (IPDomainMaps.containsKey(fakeIP));

            DomainIPMaps.put(domainString, fakeIP);
            IPDomainMaps.put(fakeIP, domainString);
        }
        Log.d("REPLACE>", "fakeIP = [" + domainString + "]");
        return fakeIP;
    }

    private boolean dnsPollution(byte[] rawPacket, DnsPacket dnsPacket) {
        if (dnsPacket.Header.QuestionCount > 0) {
            Question question = dnsPacket.Questions[0];
            if (question.Type == 1) {
                int realIP = getFirstIP(dnsPacket);
//                todo check this
//                if (ProxyConfigLoader.getsInstance().needProxy(question.Domain, realIP)) {
                int fakeIP = getOrCreateFakeIP(question.Domain);
                tamperedDnsResponse(rawPacket, dnsPacket, fakeIP);
                if (IS_DEBUG)
                    System.out.printf("FakeDns: %s=>%s(%s)\n", question.Domain, ProxyUtils.ipIntToString(realIP), ProxyUtils.ipIntToString(fakeIP));
                return true;
//                }
            }
        }
        return false;
    }

    private void OnDnsResponseReceived(IPHeader ipHeader, UDPHeader udpHeader, DnsPacket dnsPacket) {
        Log.d("TODEL", "OnDnsResponseReceived() called with: ipHeader = [" + ipHeader + "], udpHeader = [" + udpHeader + "], dnsPacket = [" + dnsPacket + "]");
        QueryState state = null;
        synchronized (mQueryArray) {
            state = mQueryArray.get(dnsPacket.Header.ID);
            if (state != null) {
                mQueryArray.remove(dnsPacket.Header.ID);
            }
        }

        if (state != null) {
            //DNS pollution, polluting overseas websites by default
            dnsPollution(udpHeader.m_Data, dnsPacket);

            dnsPacket.Header.setID(state.ClientQueryID);
            ipHeader.setSourceIP(state.RemoteIP);
            ipHeader.setDestinationIP(state.ClientIP);
            ipHeader.setProtocol(IPHeader.UDP);
            ipHeader.setTotalLength(20 + 8 + dnsPacket.Size);
            udpHeader.setSourcePort(state.RemotePort);
            udpHeader.setDestinationPort(state.ClientPort);
            udpHeader.setTotalLength(8 + dnsPacket.Size);

            LocalVpnService.getInstance().sendUDPPacket(ipHeader, udpHeader);
        }
    }

    private int getIPFromCache(String domain) {
        Integer ip = DomainIPMaps.get(domain);
        if (ip == null) {
            return 0;
        } else {
            return ip;
        }
    }

    private boolean reallyNeedToInterceptThisDns(IPHeader ipHeader, UDPHeader udpHeader, DnsPacket dnsPacket) {
        Question question = dnsPacket.Questions[0];
       Log.d(" TODEL ","DNS Query intercepted> " + Arrays.toString(dnsPacket.Questions));
        Log.d(" TODEL ","DNS Query data> " + question.toString());
        if (question.Type == 1) {

//            int fakeIP = getOrCreateFakeIP(question.Domain);
//            tamperedDnsResponse(ipHeader.mData, dnsPacket, fakeIP);
//
//            if (IS_DEBUG)
//                System.out.printf("interceptDns FakeDns: %s=>%s\n", question.Domain, ProxyUtils.ipIntToString(fakeIP));

            int sourceIP = ipHeader.getSourceIP();
            short sourcePort = udpHeader.getSourcePort();
            ipHeader.setSourceIP(ipHeader.getDestinationIP());
            ipHeader.setDestinationIP(sourceIP);
            ipHeader.setTotalLength(20 + 8 + dnsPacket.Size);
            udpHeader.setSourcePort(udpHeader.getDestinationPort());
            udpHeader.setDestinationPort(sourcePort);
            udpHeader.setTotalLength(8 + dnsPacket.Size);
            LocalVpnService.getInstance().sendUDPPacket(ipHeader, udpHeader);
            return true;
//            }
        }
        return false;
    }

    private void clearExpiredQueries() {
        long now = System.nanoTime();
        for (int i = mQueryArray.size() - 1; i >= 0; i--) {
            QueryState state = mQueryArray.valueAt(i);
            long QUERY_TIMEOUT_NS = 10 * 1000000000L;
            if ((now - state.QueryNanoTime) > QUERY_TIMEOUT_NS) {
                mQueryArray.removeAt(i);
            }
        }
    }

    public void onDnsRequestReceived(IPHeader ipHeader, UDPHeader udpHeader, DnsPacket dnsPacket) {
        Log.d("TODEL", "onDnsRequestReceived() called with: ipHeader = [" + ipHeader + "], udpHeader = [" + udpHeader + "], dnsPacket = [" + dnsPacket + "]");
        if (!reallyNeedToInterceptThisDns(ipHeader, udpHeader, dnsPacket)) {
            
            //Simply Forward  DNS
            QueryState state = new QueryState();
            state.ClientQueryID = dnsPacket.Header.ID;
            state.QueryNanoTime = System.nanoTime();
            state.ClientIP = ipHeader.getSourceIP();
            state.ClientPort = udpHeader.getSourcePort();
            state.RemoteIP = ipHeader.getDestinationIP();
            state.RemotePort = udpHeader.getDestinationPort();

            // Conversion QueryID
            mQueryID++;// increase ID
            dnsPacket.Header.setID(mQueryID);

            synchronized (mQueryArray) {
                clearExpiredQueries();//Clear outdated queries to reduce memory overhead.
                mQueryArray.put(mQueryID, state);// Linked data
            }

            InetSocketAddress remoteAddress = new InetSocketAddress(ProxyUtils.ipIntToInet4Address(state.RemoteIP), state.RemotePort);
            DatagramPacket packet = new DatagramPacket(udpHeader.m_Data, udpHeader.m_Offset + 8, dnsPacket.Size);
            packet.setSocketAddress(remoteAddress);

            try {
                if (LocalVpnService.getInstance().protect(mClient)) {
                    mClient.send(packet);
                } else {
                    System.err.println("VPN protect udp socket failed.");
                }
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }
}