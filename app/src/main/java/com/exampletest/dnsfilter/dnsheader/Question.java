package com.exampletest.dnsfilter.dnsheader;

import java.nio.ByteBuffer;

public class Question {
    public String mDomain;
    public short mType;
    public short mClass;

    private int offset;

    public int Offset() {
        return offset;
    }

    private int length;

    public int Length() {
        return length;
    }

    public static Question FromBytes(ByteBuffer buffer) {
        Question q = new Question();
        q.offset = buffer.arrayOffset() + buffer.position();
        q.mDomain = DnsPacket.ReadDomain(buffer, buffer.arrayOffset());
        q.mType = buffer.getShort();
        q.mClass = buffer.getShort();
        q.length = buffer.arrayOffset() + buffer.position() - q.offset;
        return q;
    }

    public void ToBytes(ByteBuffer buffer) {
        this.offset = buffer.position();
        DnsPacket.WriteDomain(this.mDomain, buffer);
        buffer.putShort(this.mType);
        buffer.putShort(this.mClass);
        this.length = buffer.position() - this.offset;
    }

    @Override
    public String toString() {
        return ("Domain [" + mDomain + "], Type " + mType + ", Class " + mClass);
    }

    public String toRespStr() {
        //            example.com&type=a&do=1'

        return mDomain + "&type=a&do=" + mClass;
    }
}
