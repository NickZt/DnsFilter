package com.exampletest.dnsfilter.tunnel;

import android.annotation.SuppressLint;


import com.exampletest.dnsfilter.dns.LocalVpnService;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

import static com.exampletest.dnsfilter.utils.ProxyUtils.IS_DEBUG;


public abstract class Tunnel {

    final static ByteBuffer GL_BUFFER = ByteBuffer.allocate(20000);
    public static long SessionCount;

    protected abstract void onConnected(ByteBuffer buffer) throws Exception;

    protected abstract boolean isTunnelEstablished();

    protected abstract void beforeSend(ByteBuffer buffer) throws Exception;

    protected abstract void afterReceived(ByteBuffer buffer) throws Exception;

    protected abstract void onDispose();

    private SocketChannel m_InnerChannel;
    private ByteBuffer m_SendRemainBuffer;
    private Selector m_Selector;
    private Tunnel m_BrotherTunnel;
    private boolean m_Disposed;
    private InetSocketAddress m_ServerEP;
    protected InetSocketAddress m_DestAddress;

    public Tunnel(SocketChannel innerChannel, Selector selector) {
        this.m_InnerChannel = innerChannel;
        this.m_Selector = selector;
        SessionCount++;
    }

    public Tunnel(InetSocketAddress serverAddress, Selector selector) throws IOException {
        SocketChannel innerChannel = SocketChannel.open();
        innerChannel.configureBlocking(false);
        this.m_InnerChannel = innerChannel;
        this.m_Selector = selector;
        this.m_ServerEP = serverAddress;
        SessionCount++;
    }

    public void setBrotherTunnel(Tunnel brotherTunnel) {
        m_BrotherTunnel = brotherTunnel;
    }

    public void connect(InetSocketAddress destAddress) throws Exception {
        if (LocalVpnService.getInstance().protect(m_InnerChannel.socket())) {//protection socket Don't go vpn
            m_DestAddress = destAddress;
            m_InnerChannel.register(m_Selector, SelectionKey.OP_CONNECT, this);//Register connection event
            m_InnerChannel.connect(m_ServerEP);// Connection target
        } else {
            throw new Exception("VPN protect socket failed.");
        }
    }

    protected void beginReceive() throws Exception {
        if (m_InnerChannel.isBlocking()) {
            m_InnerChannel.configureBlocking(false);
        }
        m_InnerChannel.register(m_Selector, SelectionKey.OP_READ, this);//Register read event
    }


    protected boolean write(ByteBuffer buffer, boolean copyRemainData) throws Exception {
        int bytesSent;
        while (buffer.hasRemaining()) {
            bytesSent = m_InnerChannel.write(buffer);
            if (bytesSent == 0) {
                break;//Can't send anymore, terminate the loop
            }
        }

        if (buffer.hasRemaining()) {//The data has not been sent
            if (copyRemainData) {//Copy the remaining data, then listen to the write event, and write when it becomes available.
                //Copy remaining data
                if (m_SendRemainBuffer == null) {
                    m_SendRemainBuffer = ByteBuffer.allocate(buffer.capacity());
                }
                m_SendRemainBuffer.clear();
                m_SendRemainBuffer.put(buffer);
                m_SendRemainBuffer.flip();
                m_InnerChannel.register(m_Selector, SelectionKey.OP_WRITE, this);//Register write event
            }
            return false;
        } else {//Sent
            return true;
        }
    }

    protected void onTunnelEstablished() throws Exception {
        this.beginReceive();//Start receiving data
        m_BrotherTunnel.beginReceive();//Brothers should start collecting data too
    }

    @SuppressLint("DefaultLocale")
    public void onConnectable() {
        try {
            if (m_InnerChannel.finishConnect()) {//connection succeeded
                onConnected(GL_BUFFER);//Notify the subclass that TCP is connected, and the subclass can implement handshake etc. according to the protocol.
            } else {//Connection failed
                LocalVpnService.getInstance().writeLog("Error: connect to %s failed.", m_ServerEP);
                this.dispose();
            }
        } catch (Exception e) {
            LocalVpnService.getInstance().writeLog("Error: connect to %s failed: %s", m_ServerEP, e);
            this.dispose();
        }
    }

    public void onReadable(SelectionKey key) {
        try {
            ByteBuffer buffer = GL_BUFFER;
            buffer.clear();
            int bytesRead = m_InnerChannel.read(buffer);
            if (bytesRead > 0) {
                buffer.flip();
                afterReceived(buffer);//Let the subclass handle it first, such as decrypting data.
                if (isTunnelEstablished() && buffer.hasRemaining()) {//Forward the read data to the brother.
                    m_BrotherTunnel.beforeSend(buffer);//Before sending, let the subclass handle it, such as encryption.
                    if (!m_BrotherTunnel.write(buffer, true)) {
                        key.cancel();//Brothers can't bear it, so cancel the read event.
                        if (IS_DEBUG)
                            System.out.printf("%s can not read more.\n", m_ServerEP);
                    }
                }
            } else if (bytesRead < 0) {
                this.dispose();//The connection is closed and resources are released.
            }
        } catch (Exception e) {
            e.printStackTrace();
            this.dispose();
        }
    }

    public void onWritable(SelectionKey key) {
        try {
            this.beforeSend(m_SendRemainBuffer);//Before sending, let the subclass handle it, such as encryption.
            if (this.write(m_SendRemainBuffer, false)) {//If the remaining data has been sent
                key.cancel();//Cancel the write event.
                if (isTunnelEstablished()) {
                    m_BrotherTunnel.beginReceive();//After the data is sent here, inform the brothers that the data can be received.
                } else {
                    this.beginReceive();//Start receiving proxy server response data
                }
            }
        } catch (Exception e) {
            this.dispose();
        }
    }

    public void dispose() {
        disposeInternal(true);
    }

    void disposeInternal(boolean disposeBrother) {
        if (m_Disposed) {
            return;
        } else {
            try {
                m_InnerChannel.close();
            } catch (Exception e) {
            }

            if (m_BrotherTunnel != null && disposeBrother) {
                m_BrotherTunnel.disposeInternal(false);//The resources of the brothers are also released.
            }

            m_InnerChannel = null;
            m_SendRemainBuffer = null;
            m_Selector = null;
            m_BrotherTunnel = null;
            m_Disposed = true;
            SessionCount--;

            onDispose();
        }
    }
}
