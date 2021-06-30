package ElGamal_Cryptosystem;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;


import java.io.File;
import java.math.BigInteger;

// EC-ElGamal Cryptosystem
public class ElGamalDemo {

    public static BigInteger BruteForce(Element g, Element ciphertext, Element sk, Field Zr_2){
        BigInteger i;
        for(i = BigInteger.ZERO;;i = i.add(BigInteger.ONE)){
            Element transformed_message = Zr_2.newElement().set(i);
            if(g.duplicate().powZn(transformed_message).equals(ciphertext)){
                return transformed_message.toBigInteger();
            }
        }
    }
    public static BigInteger BSGS(Element g, Element ciphertext, Element sk, Field Zr_1) {
        BigInteger upper_bound = new BigInteger("10000");
        BigInteger i, j, message = null;
        boolean flag = false;
        for (i = BigInteger.ZERO; i.compareTo(upper_bound) < 0; i = i.add(BigInteger.ONE)) {
            for (j = BigInteger.ZERO; j.compareTo(upper_bound) < 0; j = j.add(BigInteger.ONE)) {
                Element l = Zr_1.newElement().set(i);
                Element k = Zr_1.newElement().set(j);
                if (g.duplicate().powZn(l).equals(ciphertext.duplicate().div(g.duplicate().powZn(k.duplicate().mulZn(sk))))) {
                    message = k.duplicate().mulZn(sk).add(l.duplicate()).toBigInteger();
                    System.out.println(message);
                    System.out.println("Found!!!!");
                    return message;
                }
                // System.out.println("i: " + i.toString() + " j: " + j.toString());
            }
        }
        return message;
    }

    public static void main(String[] args) {
//        int rBits = 32;
//        int qBits = 128;
//        TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
//        PairingParameters s = pg.generate();
//        Pairing bp = PairingFactory.getPairing(s);
        Pairing bp = PairingFactory.getPairing("a.properties");
        // 生成椭圆曲线群
        Field G1 = bp.getG1();
        // 生成乘法循环群
        Field Zr = bp.getZr();
        // 获取群中生成元
        Element g_1 = G1.newRandomElement();
        // 获取椭圆曲线群的阶
        BigInteger q = G1.getOrder();

        // 获取私钥x和参数r
        Element x = Zr.newRandomElement();
        Element r = Zr.newRandomElement();

        Element m2 = Zr.newElement();
        m2.set(new BigInteger("50"));

        Element m3 = Zr.newElement().set(new BigInteger("25"));
        Element m4 = Zr.newElement().set(new BigInteger("35"));

        // 生成公钥pk = x*G1
        Element pk = g_1.duplicate().powZn(x);
        // 加密过程
        // Map function: M = m*g1
        Element M_1 = g_1.duplicate().powZn(m2);
        Element M_2 = g_1.duplicate().powZn(m3);
        Element M_3 = g_1.duplicate().powZn(m4);

        System.out.println("===Encryption Procedure===");
        long startMill1 = System.currentTimeMillis();
        Element C_a_1 = g_1.duplicate().powZn(r);
        Element C_b_1 = M_1.duplicate().mul(pk.duplicate().powZn(r));
        Element C_a_2 = g_1.duplicate().powZn(r);
        Element C_b_2 = M_2.duplicate().mul(pk.duplicate().powZn(r));
        Element C_a_3 = g_1.duplicate().powZn(r);
        Element C_b_3 = M_3.duplicate().mul(pk.duplicate().powZn(r));
        long endMill1 = System.currentTimeMillis();
        System.out.println("Encryption Execution Time:" + String.valueOf(endMill1 - startMill1));
        // byte[] C_a_trans = C_a.toBytes();
        // byte[] C_b_trans = C_b.toBytes();
        Element aggregated_result_A = C_a_1.duplicate().add(C_a_2).add(C_a_3);
        Element aggregated_result_B = C_b_1.duplicate().add(C_b_2).add(C_b_3);

        // 解密过程
        // ciphertext = C_b - x*C_a
        System.out.println("===Decryption Procedure===");
        Element ciphertext = aggregated_result_B.duplicate().div(aggregated_result_A.powZn(x));
        // ciphertext = m*g_1 -> how to get m?
        // reMap function1: Brute Force
        long startMill2 = System.currentTimeMillis();
        BigInteger plaintext1 = BruteForce(g_1, ciphertext, x, Zr);
        long endMill2 = System.currentTimeMillis();
        System.out.println("Decryption Execution Time:" + String.valueOf(endMill2 - startMill2));
        System.out.println("Result:" + plaintext1.toString());
//        long startMill2 = System.nanoTime();
//        BigInteger plaintext2 = BSGS(g_1, ciphertext, x, Zr);
//        long endMill2 = System.nanoTime();
//        System.out.println("Decryption Execution Time in Method2 :" + String.valueOf(endMill2 - startMill2));
//        System.out.println("Result2: " + plaintext2.toString());
        System.out.println("===Decryption Complete===");
    }

}
