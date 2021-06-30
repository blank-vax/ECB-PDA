import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.math.BigInteger;

public class CC {
    private Pairing bp;
    private Field G1, Zp;
    private int omega;
    private Element g1, random_alpha, random_x, Q, x, Y;

    public CC() throws IOException {
        init();
    }

    private void init() throws IOException {
        bp = PairingFactory.getPairing("Parameters_file/b.properties");
        G1 = bp.getG1();
        Zp = bp.getZr();
        omega = 2;
        g1 = Util.readElement("g1", bp);
        Q = Util.readElement("Q", bp);
        random_alpha = Util.readElement("random_alpha", bp);
        random_x = Util.readElement("random_x", bp);
        x = Zp.newRandomElement();
        Y = g1.duplicate().powZn(x);
        Util.setPairing(bp);
        Util.writeElement(Y, "CC_Parameters/Y", bp);
    }

    // 读取SD传输的数据
    public Element[] parameters_Load(int ID) throws IOException {
        Element[] SD_Params = new Element[3];
        SD_Params[0] = Util.readElement("SD_Parameters/Ver_pk" + String.valueOf(ID), bp);
        SD_Params[1] = Util.readElement("SD_Parameters/alpha" + String.valueOf(ID), bp);
        SD_Params[2] = Util.readElement("SD_Parameters/beta" + String.valueOf(ID), bp);
        return SD_Params;
    }

    // SD注册过程中CC对注册知识进行验证
    // Return true if pass, else return false
    public boolean registration_Verification(Element[] Params_from_SD_to_CC) {
        Element Ver_pk = Params_from_SD_to_CC[0];
        Element alpha = Params_from_SD_to_CC[1];
        Element beta = Params_from_SD_to_CC[2];
        if (alpha.equals(g1.duplicate().powZn(beta).mul(Ver_pk.duplicate().powZn(Util.hashFromG1ToZp(alpha))))) {
            return true;
        } else
            return false;
    }

    // CC生成ak
    public void ak_generation(int ID) throws IOException {
        Element t = Zp.newRandomElement();
        Element ak1 = g1.duplicate().powZn(random_alpha).mul(Y.duplicate().powZn(t));
        Element ak2 = Q.duplicate().powZn(t);
        Element ak3 = g1.duplicate().powZn(t);
        Util.writeElement(ak1, "CC_Parameters/ak1" + ID, bp);
        Util.writeElement(ak2, "CC_Parameters/ak2" + ID, bp);
        Util.writeElement(ak3, "CC_Parameters/ak3" + ID, bp);
    }

    // 聚合结果签名验证
    public boolean Aggregation_Result_Ver() throws IOException {
        Element Aggregation_Sig = Util.readElement("ES_Parameters/Aggregation_Sig", bp);
        Element Y_j = Util.readElement("ES_Parameters/Y_j", bp);
        Element concated_result = Util.readElement("ES_Parameters/Concated_Result", bp);
        if ((bp.pairing(g1, Aggregation_Sig).isEqual(bp.pairing(Y_j, concated_result)))) {
            return true;
        } else
            return false;
    }

    /**
     * ElGamal 生成密文
     *
     * @param g
     * @param ciphertext
     * @param Zr_2
     * @return
     */
    public Element BruteForce(Element g, Element ciphertext, Field Zr_2) {
        BigInteger i;
        for (i = BigInteger.ZERO; ; i = i.add(BigInteger.ONE)) {
            Element transformed_message = Zr_2.newElement().set(i);
            if (g.duplicate().powZn(transformed_message).equals(ciphertext)) {
                return transformed_message;
            }
        }
    }

    // 结果读取并解密
    public void Decryption() throws IOException {
        Element C_A = Util.readElement("Aggregated_Result_A", bp);
        Element C_B = Util.readElement("Aggregated_Result_B", bp);
        Element sk = Util.readElement("sk", bp);
        // 获取混淆之后的数据M
        Element M = C_B.duplicate().div(C_A.duplicate().powZn(sk));
        // 进行数据解密
        Element m = BruteForce(g1, M, Zp);
        // 逆混淆
        for (int i = 0; i < omega; i++) {
            m = m.duplicate().sub(Util.readElement("Symbols/symbol" + "" + i, bp));
        }
        System.out.println("Aggregated result is " + m.toString());
        Util.writeElement(m, "Aggregated_Plaintext", bp);
    }

    // 生成回复结果
    public void getResponse() throws IOException {
        // 获取聚合结果
        Element Aggregated_plaintext = Util.readElement("Aggregated_Plaintext", bp);
        // 处理聚合结果
        // Mr = 2*AP
        Element AP_Processed = Aggregated_plaintext.duplicate().mul(Zp.newElement().set(new BigInteger("2")));
        Util.writeElement(AP_Processed, "Processed_Result", bp);
        Element random_beta = Zp.newRandomElement();
        Element C_1 = AP_Processed.duplicate().mul(Util.transformFromGtToZp(bp.pairing(g1.duplicate().powZn(random_alpha), g1.duplicate().powZn(random_beta))));
        Element C_2 = g1.duplicate().powZn(random_beta);
        Element C_3 = Y.duplicate().div(Q).powZn(random_beta);
        Util.writeElement(random_beta, "CC_Parameters/random_beta", bp);
        Util.writeElement(C_1, "CC_Parameters/C_1", bp);
        Util.writeElement(C_2, "CC_Parameters/C_2", bp);
        Util.writeElement(C_3, "CC_Parameters/C_3", bp);
        long TimeStamp_CC = System.currentTimeMillis();
        Element rsp_hash = Util.hashFromStringToG1(C_1.toString() + C_2.toString() + C_3.toString() + String.valueOf(TimeStamp_CC));
        Util.writeElement(rsp_hash, "CC_Parameters/rsp_hash", bp);
        Element AP_Processed_Sig = rsp_hash.duplicate().powZn(x);
        Util.writeElement(AP_Processed_Sig, "CC_Parameters/AP_Processed_Sig", bp);
    }

}
