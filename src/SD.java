import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.math.BigInteger;


public class SD {
    public Pairing bp;
    private Element ak1, ak2, ak3;
    public Field G1, Zp;
    private int Identity;
    public Element g1;
    private Element r, s, u;
    private Element Sig_sk, Ver_pk;
    private Element y, z;
    private Element C_a, C_b, C_1, C_2, C_3;
    private Element random_alpha, random_beta;

    public SD(int ID) throws IOException {
        this.Identity = ID;
        init();
    }

    private void init() throws IOException {
        this.bp = PairingFactory.getPairing("Parameters_file/b.properties");
        this.G1 = bp.getG1();
        this.Zp = bp.getZr();
        this.g1 = Util.readElement("g1", bp);
        Util.setPairing(bp);
    }

    // 注册函数
    public void registration() throws IOException {
        Sig_sk = Zp.newRandomElement();
        Ver_pk = g1.duplicate().powZn(Sig_sk);
        // 选择盲因子k
        Element k = Zp.newRandomElement();
        // 获取时间戳
        long TimeStamp = System.currentTimeMillis();
        // 生成r_i
        r = Util.hashFromStringToZp(Identity + String.valueOf(TimeStamp) + k.toString());
        Util.writeElement(r, "SD_Parameters/r"+ Identity, bp);
        // 生成注册知识
        Element alpha = g1.duplicate().powZn(r);
        Element beta = r.duplicate().sub(Sig_sk.duplicate().mul(Util.hashFromG1ToZp(alpha)));
        Util.writeElement(Ver_pk, "SD_Parameters/Ver_pk"+ Identity, bp);
        Util.writeElement(alpha, "SD_Parameters/alpha"+ Identity, bp);
        Util.writeElement(beta, "SD_Parameters/beta"+ Identity, bp);
    }

    // 离线签名生成
    public void Off_Sig_Generation() throws IOException {
        // SD->ES:
        // T_off = String.valueOf(ID)+String.valueOf(TimeStamp)+BLS_signature.toString()+H_ch.toString();
        // SD->CC
        // Element[] Ver_on = {g1, g2, g3}
        Element[] St = new Element[3];
        // 随机选择整数y,z,s,u
        y = Zp.newRandomElement();
        z = Zp.newRandomElement();
        s = Zp.newRandomElement();
        u = Zp.newRandomElement();

        Element g2 = g1.duplicate().powZn(y);
        Element g3 = g1.duplicate().powZn(z);
        Util.writeElement(g2, "Ver_on/g2"+ Identity, bp);
        Util.writeElement(g3, "Ver_on/g3"+ Identity, bp);


        Element H_ch = g1.duplicate().powZn(r).mul(g2.duplicate().powZn(s)).mul(g3.duplicate().powZn(u));
        System.out.println("The length of H_ch is: " + H_ch.getLengthInBytes());

        Util.writeElement(H_ch, "SD_Parameters/H_ch"+ Identity, bp);
        Element BLS_signature = Util.hashFromStringToG1(H_ch.toString()).powZn(Sig_sk);
        System.out.println("The length of BLS signature is " + BLS_signature.getLengthInBytes());
        Util.writeElement(BLS_signature, "SD_Parameters/Off_Sig"+ Identity, bp);
    }

    // 使用ElGamal进行数据加密
    public void Encryption(BigInteger message) throws IOException {
        Element pk = Util.readElement("pk", bp);
        Element plaintext = Zp.newElement().set(message);
        // 存储随机数r
        Element random_factor = Zp.newRandomElement();
        Util.writeElement(random_factor, "SD_Parameters/random_factor", bp);
        // 从TA生成的symbol中读取对应的混淆数据
        Element symbol = Util.readElement("Symbols/symbol" + String.valueOf(Identity-1), bp);
        // Data Shuffle
        // M_i = m_i+symbol_i
        Element final_plaintext = plaintext.duplicate().add(symbol);
        // C_a = r*g1
        // C_b = m*g1+r*Y
        C_a = g1.duplicate().powZn(random_factor);
        C_b = g1.duplicate().powZn(final_plaintext).mul(pk.duplicate().powZn(random_factor));
        System.out.println("The length of C_a is: " + C_a.getLengthInBytes());

        Util.writeElement(C_a, "Ciphertext/C_a" + Identity, bp);
        Util.writeElement(C_b, "Ciphertext/C_b" + Identity, bp);
    }

    // 在线签名生成
    public void On_Sig_Generation() throws IOException {
        Element ver_s = Zp.newRandomElement();
        Util.writeElement(ver_s, "Ver_on/ver_s"+ Identity, bp);
        Element ver_c = Zp.newRandomElement();
        Util.writeElement(ver_c, "Ver_on/ver_c"+ Identity, bp);
        Element ver_u = (r.duplicate().sub(ver_c).add((s.duplicate().sub(ver_s)).mul(y)).add(u.duplicate().mul(z))).mul(z.duplicate().invert());
        Util.writeElement(ver_u, "Ver_on/ver_u"+ Identity, bp);
    }

    //验证ES广播结果
    public boolean ES_rsp_Ver() throws IOException{
        C_1 = Util.readElement("CC_Parameters/C_1", bp);
        C_2 = Util.readElement("CC_Parameters/C_2", bp);
        C_3 = Util.readElement("CC_Parameters/C_3", bp);
        ak1 = Util.readElement("CC_Parameters/ak1"+ Identity, bp);
        ak2 = Util.readElement("CC_Parameters/ak2"+ Identity, bp);
        ak3 = Util.readElement("CC_Parameters/ak3"+ Identity, bp);
        random_alpha = Util.readElement("random_alpha", bp);
        random_beta = Util.readElement("CC_Parameters/random_beta", bp);
        Element bp_left = bp.pairing(C_2, ak1).div((bp.pairing(C_2, ak2).mul(bp.pairing(C_3, ak3))));
        Element bp_right = bp.pairing(g1.duplicate().powZn(random_alpha), g1.duplicate().powZn(random_beta));
//        if (bp.pairing(C_2, ak1).div(bp.pairing(C_2, ak2).mul(bp.pairing(C_3, ak3))).isEqual(bp.pairing(g1.duplicate().powZn(random_alpha), g1.duplicate().powZn(random_beta)))) {
//            return true;
//        }
//        else
//            return false;
        if(bp_left.isEqual(bp_right))
            return true;
        else
            return false;
    }

    // 获取回复结果M_R
    public void getRsp() throws IOException {
        C_1 = Util.readElement("CC_Parameters/C_1", bp);
        Element AP_Processed = C_1.duplicate().div(Util.transformFromGtToZp(bp.pairing(g1.duplicate().powZn(random_alpha), g1.duplicate().powZn(random_beta))));
        Element rsp = Util.readElement("Processed_Result", bp);
        if(AP_Processed.isEqual(rsp)){
            System.out.println("Response Succeed!!");
            System.out.println(AP_Processed);
        }
    }
}
