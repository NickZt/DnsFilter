package com.exampletest.dnsfilter.dnsheader;

import androidx.annotation.NonNull;

import com.exampletest.dnsfilter.utils.ProxyUtils;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Locale;

public class DnsPacket {
    public DnsHeader Header;
    public Question[] Questions;
    public Resource[] Resources;
    public Resource[] AResources;
    public Resource[] EResources;

    public int Size;

    public static DnsPacket FromBytes(ByteBuffer buffer) {
        if (buffer.limit() < 12)
            return null;
        if (buffer.limit() > 512)
            return null;

        DnsPacket packet = new DnsPacket();
        packet.Size = buffer.limit();
        packet.Header = DnsHeader.FromBytes(buffer);

        if (packet.Header.QuestionCount > 2 || packet.Header.ResourceCount > 50 || packet.Header.AResourceCount > 50 || packet.Header.EResourceCount > 50) {
            return null;
        }

        packet.Questions = new Question[packet.Header.QuestionCount];
        packet.Resources = new Resource[packet.Header.ResourceCount];
        packet.AResources = new Resource[packet.Header.AResourceCount];
        packet.EResources = new Resource[packet.Header.EResourceCount];

        for (int i = 0; i < packet.Questions.length; i++) {
            packet.Questions[i] = Question.FromBytes(buffer);
        }

        for (int i = 0; i < packet.Resources.length; i++) {
            packet.Resources[i] = Resource.FromBytes(buffer);
        }

        for (int i = 0; i < packet.AResources.length; i++) {
            packet.AResources[i] = Resource.FromBytes(buffer);
        }

        for (int i = 0; i < packet.EResources.length; i++) {
            packet.EResources[i] = Resource.FromBytes(buffer);
        }

        return packet;
    }

    public void ToBytes(ByteBuffer buffer) {
        Header.QuestionCount = 0;
        Header.ResourceCount = 0;
        Header.AResourceCount = 0;
        Header.EResourceCount = 0;

        if (Questions != null)
            Header.QuestionCount = (short) Questions.length;
        if (Resources != null)
            Header.ResourceCount = (short) Resources.length;
        if (AResources != null)
            Header.AResourceCount = (short) AResources.length;
        if (EResources != null)
            Header.EResourceCount = (short) EResources.length;

        this.Header.ToBytes(buffer);

        for (int i = 0; i < Header.QuestionCount; i++) {
            this.Questions[i].ToBytes(buffer);
        }

        for (int i = 0; i < Header.ResourceCount; i++) {
            this.Resources[i].ToBytes(buffer);
        }

        for (int i = 0; i < Header.AResourceCount; i++) {
            this.AResources[i].ToBytes(buffer);
        }

        for (int i = 0; i < Header.EResourceCount; i++) {
            this.EResources[i].ToBytes(buffer);
        }
    }

    public static String ReadDomain(ByteBuffer buffer, int dnsHeaderOffset) {
        StringBuilder sb = new StringBuilder();
        int len = 0;
        while (buffer.hasRemaining() && (len = (buffer.get() & 0xFF)) > 0) {
            if ((len & 0xc0) == 0xc0)// pointer The upper 2 bits are 11 indicating pointers. Such as:1100 0000
            {
                // The value of the pointer is the last 6 bits of the previous byte plus the 8 bits of the next byte, a total of 14 bits.。
                int pointer = buffer.get() & 0xFF;// Low 8 bits
                pointer |= (len & 0x3F) << 8;// High 6

                ByteBuffer newBuffer = ByteBuffer.wrap(buffer.array(), dnsHeaderOffset + pointer, dnsHeaderOffset + buffer.limit());
                sb.append(ReadDomain(newBuffer, dnsHeaderOffset));
                return sb.toString();
            } else {
                while (len > 0 && buffer.hasRemaining()) {
                    sb.append((char) (buffer.get() & 0xFF));
                    len--;
                }
                sb.append('.');
            }
        }

        if (len == 0 && sb.length() > 0) {
            sb.deleteCharAt(sb.length() - 1);//Remove the dot at the end（.）
        }
        return sb.toString();
    }

    public static void WriteDomain(String domain, ByteBuffer buffer) {
        if (domain == null || domain == "") {
            buffer.put((byte) 0);
            return;
        }

        String[] arr = domain.split("\\.");
        for (String item : arr) {
            if (arr.length > 1) {
                buffer.put((byte) item.length());
            }

            for (int i = 0; i < item.length(); i++) {
                buffer.put((byte) item.codePointAt(i));
            }
        }
    }

    @Override
    public String toString() {
        return "DnsPacket{" +
                "Header=" + Header.toString() +
                ", Questions=" + Arrays.toString(Questions) +
                ", Resources=" + Arrays.toString(Resources) +
                ", AResources=" + Arrays.toString(AResources) +
                ", EResources=" + Arrays.toString(EResources) +
                ", Size=" + Size +
                '}';
    }
}