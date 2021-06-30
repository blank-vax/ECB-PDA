import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Field;

import java.io.File;

public class BLS {

//    public static void main(String[] args){
//        // Initialization
//        Pairing bp = PairingFactory.getPairing("a.properties");
//        Field G1 = bp.getG1();
//        Field Zr = bp.getZr();
//        Element g = G1.newRandomElement();
//        Element x = Zr.newRandomElement();
//        Element g_x = g.duplicate().powZn(x);
//
//        // Signing
//        String test_message = "message";
//        byte[] m_hash = Integer.toString(test_message.hashCode()).getBytes();
//        Element h = G1.newElementFromHash(m_hash, 0, m_hash.length);
//        Element sig = h.duplicate().powZn(x);
//
//        // Verification
//        Element pl = bp.pairing(g, sig);
//        Element pr = bp.pairing(h, g_x);
//        if(pl.isEqual(pr))
//            System.out.println("Yes");
//        else
//            System.out.println("No");
//
//    }

}
