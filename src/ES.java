import com.sun.xml.internal.bind.v2.model.core.ID;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.security.interfaces.ECKey;
import java.sql.Time;
import java.util.Scanner;

public class ES {
    public Pairing bp;
    public Field G1, Zp;
    public int ID_j = 1;
    private Element g1, g2, g3;
    private Element X_j, Y_j;
    private Element C_A, C_B;

    public ES() throws IOException {
//        System.out.println("Please input the ID number of Edge Server: ");
//        Scanner parameters_input = new Scanner(System.in);
//        this.ID_j = parameters_input.nextInt();
        init();
    }

    private void init() throws IOException {
        bp = PairingFactory.getPairing("Parameters_file/b.properties");
        G1 = bp.getG1();
        Zp = bp.getZr();
        g1 = Util.readElement("g1", bp);
        Util.setPairing(bp);
    }


    // 离线签名验证
    public boolean Off_Sig_Verification() throws IOException {
        Element BLS_Sig = Util.readElement("SD_Parameters/Off_Sig", bp);
        Element Ver_pk = Util.readElement("SD_Parameters/Ver_pk", bp);
        Element H_ch = Util.readElement("SD_Parameters/H_ch", bp);
//        if(bp.pairing(g1, BLS_Sig).isEqual(bp.pairing(Ver_pk, Util.hashFromStringToG1(H_ch.toString())))){
//            return true;
//        }
//        else
//            return false;
        if(bp.pairing(g1, BLS_Sig).isEqual(bp.pairing(Ver_pk, Util.hashFromStringToZp(H_ch.toString())))){
            return true;
        }
        else
            return false;
    }

    // 读取参数
    public Element[] Off_Sig_Load(int omega, String filename) throws IOException{
        Element[] parameters = new Element[omega];
        for(int i = 0;i<omega;i++){
            parameters[i] = Util.readElement(filename+ (i + 1), bp);
        }
        return parameters;
    }
    // 离线签名批量验证
    public boolean Off_Sig_Batch_Verification(Element[] Y, Element[] H_ch, Element[] BLS_Sig, int omega){
        Element result_left = bp.pairing(Y[0], Util.hashFromStringToG1(H_ch[0].toString()));
        Element result_right = BLS_Sig[0];
        for(int i = 1; i<omega;i++){
            result_left = result_left.duplicate().mul(bp.pairing(Y[i], Util.hashFromStringToG1(H_ch[i].toString())));
            result_right = result_right.duplicate().mul(BLS_Sig[i]);
        }
        if(result_left.isEqual(bp.pairing(g1, result_right))){
            return true;
        }
        else
            return false;
    }

    // 在线签名验证
    public boolean On_Sig_Verification(int ID) throws  IOException{
        g2 = Util.readElement("Ver_on/g2"+ID, bp);
        g3 = Util.readElement("Ver_on/g3"+ID, bp);
        Element H_ch_left = Util.readElement("SD_Parameters/H_ch"+ ID, bp);
        Element ver_c = Util.readElement("Ver_on/ver_c"+ ID, bp);
        Element ver_s = Util.readElement("Ver_on/ver_s"+ ID, bp);
        Element ver_u = Util.readElement("Ver_on/ver_u"+ ID, bp);
        if(H_ch_left.isEqual(g1.duplicate().powZn(ver_c).mul(g2.duplicate().powZn(ver_s)).mul(g3.duplicate().powZn(ver_u)))){
            return true;
        }
        else
            return false;
    }

    // 报告读取
    public Element[] Report_Read(int omega, String filename) throws IOException{
        Element[] report_result = new Element[omega];
        for(int j = 0;j<omega;j++){
            report_result[j] = Util.readElement(filename+(j+1), bp);
        }
        return report_result;
    }

    // 报告聚合
    public void Report_Aggregation(Element[] C_a, Element[] C_b, int omega) throws IOException{
        C_A = C_a[0];
        C_B = C_b[0];
        for(int i = 1;i < omega;i++){
            C_A = C_A.duplicate().add(C_a[i]);
            C_B = C_B.duplicate().add(C_b[i]);
        }
        Util.writeElement(C_A, "Aggregated_Result_A", bp);
        Util.writeElement(C_B, "Aggregated_Result_B", bp);
    }

    // 聚合结果签名
    public void Aggregation_Result_Sig() throws IOException {
        X_j = Zp.newRandomElement();
        Y_j = g1.duplicate().powZn(X_j);
        Util.writeElement(Y_j, "ES_Parameters/Y_j", bp);
        long TimeStamp_ES = System.currentTimeMillis();
        Element concated_Result = Util.hashFromStringToG1(ID_j +C_A.toString()+C_B.toString()+ TimeStamp_ES);
        Element Aggregation_Sig = concated_Result.powZn(X_j);
        Util.writeElement(Aggregation_Sig, "ES_Parameters/Aggregation_Sig", bp);
        Util.writeElement(concated_Result, "ES_Parameters/Concated_Result", bp);
    }

    // 验证CC发送的回复结果并进行广播
    public boolean rsp_Ver() throws IOException{
        Element rsp_sig = Util.readElement("CC_Parameters/AP_Processed_Sig", bp);
        Element Y = Util.readElement("CC_Parameters/Y", bp);
        Element rsp_hash = Util.readElement("CC_Parameters/rsp_hash", bp);

        if(bp.pairing(g1, rsp_sig).isEqual(bp.pairing(Y, rsp_hash))){
            return true;
        }
        else
            return false;
    }
}
