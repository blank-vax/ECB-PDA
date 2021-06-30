import java.io.IOException;
import java.math.BigInteger;
import java.util.Scanner;
import java.lang.reflect.Proxy;

public class new_PDA implements PDA{
    // 整体流程模拟
    public static TrustAuthority TA;
    public static CC control_center;
    public SD smart_device1, smart_device2;
    public static ES edge_server;
    public static int omega = 2;

    // TA初始化函数
    public void TA_init() throws IOException {
        System.out.println("==============System Initialization=========================");
        TA = new TrustAuthority();
        TA.Init();
        System.out.println("===============Parameters Generated========================");
    }

    // 实体生成
    public void entity_generation() throws IOException{
        System.out.println("===============Entities Initialization=====================");
        control_center = new CC();
        edge_server = new ES();
        smart_device1 = new SD(1);
        smart_device2 = new SD(2);
        System.out.println("===============Entities Generation Complete=================");
    }

    // Stage1: 注册阶段
    public void registration() throws IOException{
        System.out.println("===============Registration Start====================");
        // SD1, SD2向CC注册
//        System.out.println("Please input the ID of smart device: ");
//        Scanner parameters_input = new Scanner(System.in);
//        int ID_1 = parameters_input.nextInt();
        smart_device1.registration();
        if(control_center.registration_Verification(control_center.parameters_Load(1))){
            System.out.println("Verification Passed!");
            System.out.println("Registration Information Passed!SD registration finished!");
            control_center.ak_generation(1);
            // 离线签名生成
            smart_device1.Off_Sig_Generation();
        }
        else
            System.out.println("Something Error!");
//        System.out.println("Please input the ID of smart device: ");
//        int ID_2 = parameters_input.nextInt();
        smart_device2.registration();
        if(control_center.registration_Verification(control_center.parameters_Load(2))){
            System.out.println("Verification Passed!");
            System.out.println("Registration Information Passed!SD registration finished!");
            control_center.ak_generation(2);
            // 离线签名生成
            smart_device2.Off_Sig_Generation();
        }
        else
            System.out.println("Something Error!");
    }

    // Stage2: 报告生成阶段
    public void report_generation() throws IOException{
        // 离线签名批量验证
        System.out.println("=========================Off Signature Batch Verification=====================");
        if(edge_server.Off_Sig_Batch_Verification(edge_server.Off_Sig_Load(omega, "SD_Parameters/Ver_pk"), edge_server.Off_Sig_Load(omega, "SD_Parameters/H_ch"), edge_server.Off_Sig_Load(omega, "SD_Parameters/Off_Sig"), omega)){
            System.out.println("Verification Passed!!");
            // 验证通过，进行数据加密并生成在线签名
            smart_device1.Encryption(new BigInteger("17"));
            // 在线签名生成
            smart_device1.On_Sig_Generation();
            smart_device2.Encryption(new BigInteger("35"));
            smart_device2.On_Sig_Generation();
            System.out.println("===================Report Generation Finished====================");
        }
        else
            System.out.println("Something Error!!");
    }

    // Stage3: 报告聚合阶段
    public void report_aggregation() throws IOException{
        System.out.println("================Report Aggregation=====================");
        // 分别对SD生成的数据报告进行验证
        if(edge_server.On_Sig_Verification(1) && edge_server.On_Sig_Verification(2)){
            System.out.println("Verification Passed!!!");
            // 若均通过验证，则执行数据聚合
            edge_server.Report_Aggregation(edge_server.Report_Read(omega, "Ciphertext/C_a"), edge_server.Report_Read(omega, "Ciphertext/C_b"), omega);
            // 对聚合结果进行签名
            edge_server.Aggregation_Result_Sig();
            System.out.println("=================Aggregation Finished======================");
        }
        else
            System.out.println("Something Error!!!");
    }

    // Stage4: 报告读取阶段
    public void report_read() throws  IOException{
        System.out.println("==============Report Read===============");
        // 对聚合结果进行签名验证
        if(control_center.Aggregation_Result_Ver()){
            System.out.println("Verification Passed!!!!");
            // 报告解密
            control_center.Decryption();
            System.out.println("==============Decryption Finished====================");
        }
        else
            System.out.println("Something Error!!!!");
    }

    // Stage5: 回复阶段
    public void response() throws IOException{
        // 生成回复结果并计算签名
        control_center.getResponse();
        // 验证签名
        if(edge_server.rsp_Ver()){
            System.out.println("Verification Passed!!!!!!");
            // 验证签名通过则将结果广播至SD_i
            if(smart_device1.ES_rsp_Ver()){
                // SD_i验证广播信息，若通过则获取回复
                System.out.println("Verification1 Passed!!!!!!!");
                smart_device1.getRsp();
                System.out.println("===================Smart Device1 Procedure Finished===================");
            }
            else
                System.out.println("Something Error1!!!!!!!");
            if(smart_device2.ES_rsp_Ver()){
                // SD_i验证广播信息，若通过则获取回复
                System.out.println("Verification2 Passed!!!!!!!");
                smart_device2.getRsp();
                System.out.println("===================Smart Device2 Procedure Finished===================");
            }
            else
                System.out.println("Something Error2!!!!!!!!");
        }
        else
            System.out.println("Something Error!!!!!");
    }


    public static void main(String[] args) throws IOException {
        System.out.println("=====Simulation Start======");
        new_PDA ident = new new_PDA();
        PDA identProxy = (PDA) Proxy.newProxyInstance(
                PDA.class.getClassLoader(),
                new Class[] { PDA.class }, new TimeCountProxyHandle(ident));
        // 初始化阶段
        identProxy.TA_init();
        // 交互阶段，选择1CC-1ES-2SD架构
        identProxy.entity_generation();
        // 注册阶段
        identProxy.registration();
        // 报告生成阶段
        identProxy.report_generation();
        // 报告聚合阶段
        identProxy.report_aggregation();
        // 报告读取阶段
        identProxy.report_read();
        // 回复阶段
        identProxy.response();
        System.out.println("======No Error=======");
        System.out.println("======Simulation Finish========");
    }
}
