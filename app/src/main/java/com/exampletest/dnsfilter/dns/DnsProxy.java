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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import okhttp3.ConnectionSpec;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.dnsoverhttps.DnsOverHttps;
import okhttp3.logging.HttpLoggingInterceptor;

import static com.exampletest.dnsfilter.dns.LocalVpnService.URL_DNS_GET;
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
    private static final ConcurrentHashMap<Integer, String> IPDomainMaps = new ConcurrentHashMap<Integer,
            String>();
    private static final ConcurrentHashMap<String, Integer> DomainIPMaps = new ConcurrentHashMap<String,
            Integer>();
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
            HttpLoggingInterceptor interceptor = new HttpLoggingInterceptor();
            interceptor.setLevel(HttpLoggingInterceptor.Level.BODY);
//            mOkHttpClient = new OkHttpClient();
            mOkHttpClient = new OkHttpClient.Builder()
                    .connectionSpecs(Arrays.asList(ConnectionSpec.MODERN_TLS, ConnectionSpec.COMPATIBLE_TLS,
                            ConnectionSpec.CLEARTEXT))
                    .build();
//            .newBuilder().addInterceptor(interceptor).build();
//            .dns(new DnsOverHttps.Builder().client(mOkHttpClient).url(HttpUrl.get("https://dns.google.com")
//            ).build())
            //.newBuilder().addInterceptor(interceptor).build();


//            try {
//                mDnsOverHttpsGoogleExperimental = new DnsOverHttps.Builder()
//                        .client(mOkHttpClient)
//                        .url(HttpUrl.get("https://dns.google.com/experimental"))
//                        .bootstrapDnsHosts(InetAddress.getByName("216.58.204.78"),
//                                InetAddress.getByName("2a00:1450:4009:814:0:0:0:200e"))
//                        .build();
//
//            } catch (UnknownHostException e) {
//                e.printStackTrace();
//            }
//
            mDnsOverHttpsGoogle = new DnsOverHttps.Builder()
                    .client(mOkHttpClient)
                    .url(HttpUrl.get("https://dns.google.com"))
                    .build();

            while (mClient != null && !mClient.isClosed()) {

                packet.setLength(RECEIVE_BUFFER.length - 28);
                mClient.receive(packet);

                dnsBuffer.clear();
                dnsBuffer.limit(packet.getLength());
                try {
                    DnsPacket dnsPacket = DnsPacket.FromBytes(dnsBuffer);
                    if (dnsPacket != null) {
                        onDnsResponseReceived(ipHeader, udpHeader, dnsPacket);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    LocalVpnService.getInstance().writeLog("Parse dns error: %s", e);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            Log.d(" TODEL ", "DnsResolver Thread Exited.");
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
        rPointer.setType(question.mType);
        rPointer.setClass(question.mClass);
//        rPointer.setTTL(ProxyConfigLoader.getsInstance().getDnsTTL());
        rPointer.setDataLength((short) 4);
        rPointer.setIP(newIP);

        dnsPacket.Size = 12 + question.Length() + 16;
    }

    DatagramPacket mInDnsPacket;
    private OkHttpClient mOkHttpClient;
    private DnsOverHttps mDnsOverHttpsGoogleExperimental;
    private DnsOverHttps mDnsOverHttpsGoogle;

    // proxyUrl
    private String downloadDOHdata(String data) throws Exception {
//        //            curl -i 'https://dns.google/resolve?name=example.com&type=a&do=1'
//        InetAddress tmpaddr = InetAddress.getByName("216.239.34.105");
//        Request request = new Request.Builder()
//
//                .url(URL_DNS_GET + data)
//                .addHeader("accept", "application/dns-message")
//                .addHeader("content-type", "application/dns-message").get()
//                .build();
////mDnsOverHttpsGoogleExperimental.
//        try {
//            Response response = mOkHttpClient.newCall(request).execute();
//            byte[] responseBytes = response.body().bytes();
//            String line = response.body().string();
//            Log.d("TAG", "downloadDOHdata() response.body().string() data = [" + line + "]");
////           codec= DnsRecordCodec.decodeAnswers(hostname, ByteString.of(responseBytes));
////            mInDnsPacket.setData(responseBytes);
//            return line;
////            mServerSocket.send(mPacket);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        return sendHttpReq(data);
    }

    public String sendHttpReq(String data) throws Exception {
        Log.d("TAG", "sendHttpReq() called with: data = [" + "]");
        //Instantiate a new socket
        Socket s = null;
//        s = new Socket("www.dns.google", 8080);

        if (s == null) {
            Log.d("TAG", "sendHttpReq() s == null = [" + "]");
            try {
                InetAddress tmpaddr = InetAddress.getByName("8.8.8.8");//"216.239.34.105"
                System.out.println(tmpaddr.getHostName());
                Log.d("TAG", "sendHttpReq() tmpaddr.getHostName() = [" + tmpaddr.getHostName() + "]");
                s = new Socket(tmpaddr, 80);
            } catch (Exception e) {
                Log.d("TAG", "error [" + e.getMessage() + "]");
            }

        } else {
            Log.d("TAG", "s.getInetAddress().getHostName() [" + s.getInetAddress().getHostName() + "]");
//            System.out.println(s.getInetAddress().getHostName());
        }
        try (final DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("8.8.8.8"), 8080);
            String ip = socket.getLocalAddress().getHostAddress();
            Log.d("TAG", "ip [" + ip + "]");
        }

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("google.com", 80));
        Log.d("TAG", "socket.getLocalAddress() [" + socket.getLocalAddress() + "]");

        //Instantiates a new PrintWriter passing in the sockets output stream
        PrintWriter wtr = new PrintWriter(s.getOutputStream());// s.getOutputStream()

        //Prints the request string to the output stream
        wtr.print("GET /resolve?name=example.com&type=a&do=1 HTTP/1.1 \r\n");
        wtr.print("Host: google.com \\r\\n\\r\\n");
//        wtr.println("");
        wtr.flush();

//        / Constructe a HTTP GET request
//        // The end of HTTP GET request should be \r\n\r\n
//        String request = "GET " + path + "?" + data + " HTTP/1.0\r\n"
//                + "Accept: */*\r\n" + "Host: "+host+"\r\n"
//                + "Connection: Close\r\n\r\n";
//
//        // Sends off HTTP GET request
//        out.write(request.getBytes());
//        out.flush();


        //Creates a BufferedReader that contains the server response
        BufferedReader bufRead = new BufferedReader(new InputStreamReader(s != null ? s.getInputStream() :
                null));
        String outStr, outOStr = "";


        //Prints each line of the response
        while ((outStr = bufRead.readLine()) != null) {
            outOStr = outOStr + outStr;
            System.out.println(outStr);
        }
        Log.d("TAG", "sendHttpReq() return outStr = [" + outStr + "]");

        //Closes out buffer and writer
        bufRead.close();
        wtr.close();

        try {
            SSLSocketFactory factory =
                    (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslSocket =
                    (SSLSocket) factory.createSocket("www.dns.google", 443);
            sslSocket.startHandshake();

            PrintWriter out = new PrintWriter(
                    new BufferedWriter(
                            new OutputStreamWriter(
                                    sslSocket.getOutputStream())));

            out.println("GET / HTTP/1.0");
            out.println();
            out.flush();
            if (out.checkError()) {
                System.out.println(
                        "SSLSocketClient:  java.io.PrintWriter error");
            }

            /* read response */
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                            sslSocket.getInputStream()));

            String inputLine;
            while ((inputLine = in.readLine()) != null)
                System.out.println(inputLine);

            in.close();
            out.close();
            sslSocket.close();
        } catch (Exception e) {
            Log.d("TAG", "Exception  [" + e.getMessage() + "]");
        }


        return outOStr;
    }


    // proxyUrl
    private String downloadDOHDomaindata(String data) throws Exception {
        //            curl -i 'https://dns.google/resolve?name=example.com&type=a&do=1'
        Request request = new Request.Builder()
                .url("https://dns.google/resolve?name=" + data)
                .addHeader("accept", "application/dns-message")
                .addHeader("content-type", "application/dns-message").get()
                .build();
//mDnsOverHttpsGoogleExperimental.
        try {
            Response response = mOkHttpClient.newCall(request).execute();
            byte[] responseBytes = response.body().bytes();
            String line = response.body().string();
            Log.d("TAG", "downloadDOHdata() response.body().string() data = [" + line + "]");
//           codec= DnsRecordCodec.decodeAnswers(hostname, ByteString.of(responseBytes));
//            mInDnsPacket.setData(responseBytes);
            return line;
//            mServerSocket.send(mPacket);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    private int getOrCreateSubstituteForIP(String domainString) {
        Log.d("REPLACE>", "getOrCreateSubstituteForIP called with: domainString = [" + domainString + "]");
        //todo replace this to http ask
        Integer substIP = DomainIPMaps.get(domainString);
        if (substIP == null) {
            int hashIP = domainString.hashCode();
            do {
                substIP = ProxyUtils.fakeIP(hashIP);
                hashIP++;
            } while (IPDomainMaps.containsKey(substIP));

            DomainIPMaps.put(domainString, substIP);
            IPDomainMaps.put(substIP, domainString);
        }
        Log.d("REPLACE>", "substIP = [" + domainString + "]");
        return substIP;
    }

    private boolean dnsSubstitute(byte[] rawPacket, DnsPacket dnsPacket) {
        if (dnsPacket.Header.QuestionCount > 0) {
            Question question = dnsPacket.Questions[0];
            if (question.mType == 1) {
                int realIP = getFirstIP(dnsPacket);
                int substIP = getOrCreateSubstituteForIP(question.mDomain);
                tamperedDnsResponse(rawPacket, dnsPacket, substIP);
                if (IS_DEBUG) {
                    System.out.printf("SubstitutedDns: %s=>%s(%s)\n", question.mDomain,
                            ProxyUtils.ipIntToString(realIP), ProxyUtils.ipIntToString(substIP));
                }
                return true;
            }
        }
        return false;
    }

    private void onDnsResponseReceived(IPHeader ipHeader, UDPHeader udpHeader, DnsPacket dnsPacket) {
        Log.d("TODEL",
                " on Dns Response Received with: ipHeader = [" + ipHeader + "], udpHeader = [" + udpHeader +
                        "], dnsPacket = [" + dnsPacket + "]");
        QueryState state = null;
        synchronized (mQueryArray) {
            state = mQueryArray.get(dnsPacket.Header.ID);
            if (state != null) {
                Log.d("TODEL",
                        "Dns Query Array remove key with indexOfKey = [" + mQueryArray.indexOfKey(dnsPacket.Header.ID) + "] key " + dnsPacket.Header.ID);
                mQueryArray.remove(dnsPacket.Header.ID);

            }
        }

        if (state != null) {
            dnsSubstitute(udpHeader.m_Data, dnsPacket);
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


    private boolean reallyNeedToInterceptThisDns(IPHeader ipHeader, UDPHeader udpHeader, DnsPacket dnsPacket) {
        Question question = dnsPacket.Questions[0];
        Log.d(" TODEL ", "DNS Query intercepted> " + Arrays.toString(dnsPacket.Questions));
        if (question.mType == 1) {

//            int fakeIP = getOrCreateFakeIP(question.Domain);
//            tamperedDnsResponse(ipHeader.mData, dnsPacket, fakeIP);
//
//            if (IS_DEBUG)
//                System.out.printf("interceptDns FakeDns: %s=>%s\n", question.Domain, ProxyUtils
//                .ipIntToString(fakeIP));

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
        Log.d("TODEL",
                "on Dns Request with: ipHeader = [" + ipHeader + "], udpHeader = [" + udpHeader + "], " +
                        "dnsPacket = [" + dnsPacket.toString() + "]");
//        if (!reallyNeedToInterceptThisDns(ipHeader, udpHeader, dnsPacket)) {
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
            Log.d("TODEL", "Dns Query Array saved to indexOfKey = [" + mQueryArray.indexOfKey(mQueryID) + "] " +
                    "key  " + mQueryID);
        }
        String tmpstr;

        InetSocketAddress remoteAddress =
                new InetSocketAddress(ProxyUtils.ipIntToInet4Address(state.RemoteIP), state.RemotePort);
        DatagramPacket packet = new DatagramPacket(udpHeader.m_Data, udpHeader.m_Offset + 8, dnsPacket.Size);
        packet.setSocketAddress(remoteAddress);

        try {
//            its send packet
            if (LocalVpnService.getInstance().protect(mClient)) {
                mClient.send(packet);
            }
            tmpstr = downloadDOHdata(new String(dnsPacket.Header.Data));
//            example.com&type=a&do=1'
//            tmpstr = downloadDOHDomaindata((new String(dnsPacket.Questions[0].toRespStr())));
        } catch (IOException e) {
            System.err.println(e.getMessage());
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }
}