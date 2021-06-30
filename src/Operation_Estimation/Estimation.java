package Operation_Estimation;


import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.io.IOException;
import java.math.BigInteger;

public class Estimation {

    public static TypeACurveGenerator pg;

    public static PairingParameters s;

    public static Pairing bp;

    // 初始化椭圆曲线
    public static void CurveGeneration() {
        int rBits = 32;
        int k_length = 160;
        // 选择G的阶数，即|qBits| = |k1|
        pg = new TypeACurveGenerator(rBits, k_length);
        s = pg.generate();
        bp = PairingFactory.getPairing(s);
    }


    public static void main(String[] args) throws IOException {
        Util.setPairing(bp);
        // 初始化
        CurveGeneration();
        Field G1 = bp.getG1();
        Field Zr = bp.getZr();
        Element g3, g4, g5, g6, g7, g10, g11, g12, g13;
        Element g1 = G1.newRandomElement();
        Element g2 = G1.newRandomElement();
        Element g8 = Zr.newRandomElement();
        Element g9 = Zr.newRandomElement();

        long time_count1 = 0, time_count2 = 0, time_count3 = 0, time_count4 = 0, time_count5 = 0, time_count6 = 0, time_count7 = 0, time_count8 = 0;




        g11 = bp.pairing(g2, g2);
        for (int i = 0; i < 100; i++) {

            System.out.println("1.E(Fp)上的加法运算");
            long beginTime1 = System.nanoTime();
            g3 = g1.duplicate().add(g2);
            long endTime1 = System.nanoTime();
            time_count1 += endTime1 - beginTime1;
            System.out.println("本次操作耗时:" + (endTime1 - beginTime1));

            System.out.println("2.E(Fp)上的点乘运算");
            long beginTime2 = System.nanoTime();
            g4 = g1.duplicate().mul(new BigInteger("10"));
            long endTime2 = System.nanoTime();
            time_count2 += endTime2 - beginTime2;
            System.out.println("本次操作耗时:" + (endTime2 - beginTime2));

            System.out.println("3.配对运算");
            long beginTime3 = System.nanoTime();
            g5 = bp.pairing(g1, g1);
            long endTime3 = System.nanoTime();
            time_count3 += endTime3 - beginTime3;
            System.out.println("本次操作耗时:" + (endTime3 - beginTime3));

            System.out.println("4.Gt上乘法运算");
            long beginTime4 = System.nanoTime();
            g6 = g5.duplicate().mulZn(g11);
            long endTime4 = System.nanoTime();
            time_count4 += endTime4 - beginTime4;
            System.out.println("本次操作耗时:" + (endTime4 - beginTime4));

            System.out.println("5.Gt上指数运算");
            long beginTime5 = System.nanoTime();
            g7 = g5.duplicate().powZn(g11);
            long endTime5 = System.nanoTime();
            time_count5 += endTime5 - beginTime5;
            System.out.println("本次操作耗时:" + (endTime5 - beginTime5));

            System.out.println("6.整数循环群中映射运算");
            long beginTime6 = System.nanoTime();
            g10 = g8.duplicate().add(g9).halve();
            long endTime6 = System.nanoTime();
            time_count6 += endTime6 - beginTime6;
            System.out.println("本次操作耗时:" + (endTime6 - beginTime6));

            System.out.println("7.Gt上加法运算");
            long beginTime7 = System.nanoTime();
            g12 = g5.duplicate().add(g11);
            long endTime7 = System.nanoTime();
            time_count7 += endTime7 - beginTime7;
            System.out.println("本次操作耗时:" + (endTime7 - beginTime7));

            System.out.println("8.哈希运算");
            Element H_ch = Util.readElement("H_ch", bp);
            long beginTime8 = System.nanoTime();
            g13 = Util.hashFromStringToZp(H_ch.toString());
            long endTime8 = System.nanoTime();
            time_count8 += endTime8 - beginTime8;
            System.out.println("本次操作耗时:" + (endTime8 - beginTime8));
        }
        System.out.println("Final Time of 1:" + time_count1/100);
        System.out.println("Final Time of 2:" + time_count2/100);
        System.out.println("Final Time of 3:" + time_count3/100);
        System.out.println("Final Time of 4:" + time_count4/100);
        System.out.println("Final Time of 5:" + time_count5/100);
        System.out.println("Final Time of 6:" + time_count6/100);
        System.out.println("Final Time of 7:" + time_count7/100);
        System.out.println("Final Time of 8:" + time_count8/100);
    }
}

