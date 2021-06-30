import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;


public class JPBCDemo {

//    public static void main(String[] args){
//
//        // 生成Pairing对
//        // Pairing bp = PairingFactory.getPairing("a.properties");
//
//        int rBits = 160;
//        int qBits = 512;
//        // 椭圆曲线生成器,每次生成结果不同
//        TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
//        PairingParameters pp = pg.generate();
//
//        Pairing bp = PairingFactory.getPairing(pp);
//
//
//       /* // 生成G群
//        Field G1 = bp.getG1();
//        // 生成整数群
//        Field Zr = bp.getZr();
//
//        Element g = G1.newRandomElement();
//        Element a = Zr.newRandomElement();
//        Element b = Zr.newRandomElement();
//
//        // 使用duplicate()函数实现元素g运算过程中不可变
//        // 或生成g过程中采用.getImmutable()函数
//        // 计算g^a, g^b以及e(g^a,g^b)
//        Element g_a = g.duplicate().powZn(a);
//        Element g_b = g.duplicate().powZn(b);
//        Element egg_ab = bp.pairing(g_a, g_b);
//
//        Element egg = bp.pairing(g, g);
//        // 计算a*b
//        Element ab = a.duplicate().mul(b);
//        Element egg_ab_p = egg.duplicate().powZn(ab);
//
//
//        if(egg_ab.isEqual(egg_ab_p))
//            System.out.println("Yes");
//        else
//            System.out.println("No");*/
//
//
//
//
//    }

}
