import com.sun.org.apache.xpath.internal.operations.Gt;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.io.*;
import java.math.BigInteger;
import java.util.Scanner;


public class TrustAuthority {
    private TypeACurveGenerator pg;

    private PairingParameters s;

    // generate e:G x G -> Gt
    public void CurveGeneration() throws IOException {
        int rBits = 32;
        int k_length = 160;
        // 选择G的阶数，即|qBits| = |k1|
        pg = new TypeACurveGenerator(rBits, k_length);
        s = pg.generate();
        Pairing bp = PairingFactory.getPairing(s);
        Field Zp1 = bp.getZr();
        Element Gt_order = Zp1.newElement().set(k_length);
        Util.writeElement(Gt_order, "Gt_order", bp);
        if (bp.isSymmetric()) {
            Out out = new Out("Parameters_file/b.properties");
            out.println(s);
        } else {
            System.out.println("Initial Again!");
        }
    }

    public void SetParameters(int omega) throws IOException {
        // 初始化椭圆曲线循环群G1及GT
        Pairing bp = PairingFactory.getPairing("Parameters_file/b.properties");
        Field G1 = bp.getG1();
        Field GT = bp.getGT();
        // 初始化整数循环群Zp1*
        Field Zp1 = bp.getZr();

        // g1
        Element g1 = G1.newRandomElement();
        while (g1.isEqual(G1.newElement())) {
            g1 = G1.newRandomElement();
        }
        Util.writeElement(g1, "g1", bp);
        // e:G1 x G1 -> GT bp.pairing()
        Element random_alpha = Zp1.newRandomElement();
        Element random_x = Zp1.newRandomElement();
        Element sk = Zp1.newRandomElement();
        Element Q = G1.newRandomElement();
        // Genrate e(g1, g1)^random_alpha
        Element e_result = bp.pairing(g1.duplicate(), g1.duplicate()).powZn(random_alpha);
        // Generate random_Y = g1^random_x
        Element random_Y = g1.duplicate().powZn(random_x);
        Element pk = g1.duplicate().powZn(sk);
        // 将结果保存至文件
        // 保存symboli至文件
        for (int i = 0; i < omega; i++) {
            // Element symbol = Zp1.newElement().set(BigInteger.ZERO);
            Element symbol = Zp1.newElement().set(new BigInteger(String.valueOf(i+2)));
            // Element symbol = Zp1.newRandomElement();
            Util.writeElement(symbol, "Symbols/symbol" + "" + i, bp);
        }
        // master_key = {sk, random_alpha, random_x}
        Util.writeElement(sk, "sk", bp);
        Util.writeElement(random_alpha, "random_alpha", bp);
        Util.writeElement(random_x, "random_x", bp);
        // SP_pub = {pk, k_length, G1, GT, omega, random_Y, Q, H0, H1, H2, H_ch, e_result}
        Element sd_number = Zp1.newElement().set(omega);
        Util.writeElement(pk, "pk", bp);
        Util.writeElement(Q, "Q", bp);
        Util.writeElement(e_result, "e_result", bp);
        Util.writeElement(random_Y, "random_Y", bp);
        Util.writeElement(sd_number, "sd_number", bp);
    }

    public void Init() throws IOException {
//        System.out.println("Please input the security parameters k1 and the number of smart devices omega: ");
//        Scanner parameters_input = new Scanner(System.in);
//        int k_length = parameters_input.nextInt();
        int omega = 2;
        // 生成曲线并将参数保存至"b.properties"
        CurveGeneration();
        // 初始化参数并保存至文件
        SetParameters(omega);
    }
}

