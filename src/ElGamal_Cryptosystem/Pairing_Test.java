package ElGamal_Cryptosystem;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Pairing_Test {

    public void pairing_test(){
        Pairing bp = PairingFactory.getPairing("a.properties");
        Field G1 = bp.getG1();
        Field Zr = bp.getZr();
        Element random_alpha = Zr.newRandomElement();
        Element random_beta = Zr.newRandomElement();
        Element x = Zr.newRandomElement();
        Element t = Zr.newRandomElement();

        Element g1 = G1.newRandomElement();
        Element Y = g1.duplicate().powZn(x);
        Element Q = G1.newRandomElement();
        Element C_2 = g1.duplicate().powZn(random_beta);
        Element C_3 = Y.duplicate().div(Q).powZn(random_beta);

        Element bp_left = bp.pairing(C_2, g1.duplicate().powZn(random_alpha).mul(Y.duplicate().powZn(t))).div(bp.pairing(C_2, Q.duplicate().powZn(t)).mul(bp.pairing(C_3, g1.duplicate().powZn(t))));
        Element bp_right = bp.pairing(g1.duplicate().powZn(random_alpha), g1.duplicate().powZn(random_beta));

        System.out.println(bp_left);
        System.out.println(bp_right);
        if (bp_left.isEqual(bp_right))
            System.out.println("Right!");
        else
            System.out.println("Error!!");
    }
    public static void main(String[] args){
        Pairing_Test pt = new Pairing_Test();
        pt.pairing_test();
        pt.pairing_test();

    }
}
