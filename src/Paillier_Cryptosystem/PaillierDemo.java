package Paillier_Cryptosystem;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import sun.security.provider.DSAParameters;

import java.math.*;
import java.security.*;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.*;

public class PaillierDemo {

    private BigInteger p, q, lambda;
    public BigInteger n;
    public BigInteger nsquare;
    private BigInteger g;
    private int bitLength;

    public PaillierDemo(int bitLengthVal, int certainty) {
        KeyGeneration(bitLengthVal, certainty);
    }

    /**
     * Constructs an instance of the Paillier cryptosystem with 512 bits of
     * modulus and at least 1-2^(-64) certainty of primes generation.
     */
    public PaillierDemo() {
        KeyGeneration(3072, 64);
    }

    public BigInteger[] euclidean(BigInteger a, BigInteger b)
    {
        if(b.compareTo(a) > 0)
        {
            //reverse the order of inputs, run through this method, then reverse outputs
            BigInteger[] coeffs = euclidean(b, a);
            BigInteger[] output = {coeffs[1], coeffs[0]};
            return output;
        }
        BigInteger q = a.divide(b);
        //a = q*b + r --> r = a - q*b
        BigInteger r = a.subtract(q.multiply(b));

        //when there is no remainder, we have reached the gcd and are done
        if(r.equals(BigInteger.ZERO))
        {
            BigInteger[] output = {new BigInteger("0"), new BigInteger("1")};
            return output;
        }

        //call the next iteration down (b = qr + r_2)
        BigInteger[] next = euclidean(b, r);

        BigInteger[] output = {next[1], next[0].subtract(q.multiply(next[1]))};
        return output;
    }

    //finds the least positive integer equivalent to a mod m
    public BigInteger leastPosEquiv(BigInteger a, BigInteger m)
    {
        //a eqivalent to b mod -m <==> a equivalent to b mod m
        if(m.compareTo(BigInteger.ZERO) < 0)
            return leastPosEquiv(a, m.multiply(new BigInteger("-1")));
        //if 0 <= a < m, then a is the least positive integer equivalent to a mod m
        if(a.compareTo(BigInteger.ZERO) >= 0 && a.compareTo(m) < 0)
            return a;

        //for negative a, find the least negative integer equivalent to a mod m
        //then add m
        if(a.compareTo(BigInteger.ZERO) < 0)
            return leastPosEquiv(a.multiply(new BigInteger("-1")), m).multiply(new BigInteger("-1")).add(m);

        //the only case left is that of a,m > 0 and a >= m

        //take the remainder according to the Division algorithm
        BigInteger q = a.divide(m);

        /*
         * a = qm + r, with 0 <= r < m
         * r = a - qm is equivalent to a mod m
         * and is the least such non-negative number (since r < m)
         */
        return a.subtract(q.multiply(m));
    }

    // L(x) = (x-1)/n
    public BigInteger L_function(BigInteger x, BigInteger parameter) {
        return x.subtract(BigInteger.ONE).divide(parameter);
    }

    // Generation of g
    public void g_Generation() {
        g = new BigInteger("2");
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
                .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
        /* check whether g is good. */
        if (L_function(g.modPow(lambda, nsquare), n).gcd(n).intValue() != 1) {
            System.out.println("g is not good. Choose g again.");
            System.exit(1);
        }
    }

    public void KeyGeneration(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        /*
         * Constructs two randomly generated positive BigIntegers that are
         * probably prime, with the specified bitLength and certainty.
         */
        p = new BigInteger(bitLength / 2, certainty, new Random());
        q = new BigInteger(bitLength / 2, certainty, new Random());
        n = p.multiply(q);
        nsquare = n.multiply(n);
        g_Generation();
    }

    public BigInteger CRT(BigInteger p, BigInteger q, BigInteger m_p, BigInteger m_q){
        BigInteger[] constraints = {m_p, m_q};
        BigInteger[] mods = {p, q};
        BigInteger M = BigInteger.ONE;
        BigInteger x = BigInteger.ZERO;
        for(int i = 0; i<mods.length;i++){
            M = M.multiply(mods[i]);
        }
        BigInteger[] multInv = new BigInteger[constraints.length];

        for(int i = 0;i< multInv.length;i++){
            multInv[i] = euclidean(M.divide(mods[i]), mods[i])[0];
        }
        for(int i = 0;i < mods.length;i++){
            x = x.add(M.divide(mods[i]).multiply(constraints[i]).multiply(multInv[i]));
        }
        x = leastPosEquiv(x, M);
        return x;
    }
    /**
     * Encrypts plaintext m. ciphertext c = g^m * r^n mod n^2. This function
     * automatically generates random input r (to help with encryption).
     *
     * @param m plaintext as a BigInteger
     * @return ciphertext as a BigInteger
     */
    public BigInteger Encryption(BigInteger m) {
        BigInteger r = new BigInteger(bitLength, new Random());
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    /**
     * Decrypts ciphertext c. plaintext m = L(c^lambda mod n^2) * u mod n, where
     * u = (L(g^lambda mod n^2))^(-1) mod n.
     *
     * @param c ciphertext as a BigInteger
     * @return plaintext as a BigInteger
     */
    // General Decryption
    public BigInteger Decryption(BigInteger c){
         BigInteger u = L_function(g.modPow(lambda, nsquare), n);
         return L_function(c.modPow(lambda, nsquare), n).multiply(u).mod(n);
    }
    // Fast Variant of Decryption
    // Usage of CRT
    // Scheme3: solve (g^n)^alpha = 1 mod n^2 to get alpha
    public BigInteger Fast_Decryption(BigInteger c) {
        BigInteger m_p = L_function(c.modPow(p.subtract(BigInteger.ONE), p.multiply(p)), p).multiply(L_function(g.modPow(p.subtract(BigInteger.ONE), p.multiply(p)), p).modInverse(p)).mod(p);
        BigInteger m_q = L_function(c.modPow(q.subtract(BigInteger.ONE), q.multiply(q)), q).multiply(L_function(g.modPow(q.subtract(BigInteger.ONE), q.multiply(q)), q).modInverse(q)).mod(q);
        return CRT(p, q, m_p, m_q).mod(n);
    }

    public BigInteger cipher_add(BigInteger em1, BigInteger em2) {
        return em1.multiply(em2).mod(nsquare);
    }

    /**
     * main function
     *
     * @param str intput string
     */
    public static void main(String[] str) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeyException {
        /* instantiating an object of Paillier cryptosystem */
        // Speed test
        System.out.println("--------------------------------");
        PaillierDemo p = new PaillierDemo();
        Random rand = new Random();
        // BigInteger m1 = BigInteger.valueOf(rand.nextInt()).add(new BigInteger("1048576"));
        // BigInteger m1 = new BigInteger("1234567890");
        BigInteger m1 = new BigInteger("5000");
        System.out.println(m1.toString());
        System.out.println("------------Encryption-------------");
        // Execution Time Record
        long startMill1 = System.currentTimeMillis();
        BigInteger em1 = p.Encryption(m1);
        long endMill1 = System.currentTimeMillis();
        System.out.println("Encryption Execution Time:" + String.valueOf(endMill1 - startMill1));
        System.out.println(em1.toString());
        System.out.println("------------Common Decryption-------------");
        // Execution Time Record
        long startMill2 = System.currentTimeMillis();
        BigInteger m1_recover = p.Decryption(em1);
        long endMill2 = System.currentTimeMillis();
        System.out.println("Decryption Execution Time:" + String.valueOf(endMill2 - startMill2));
        System.out.println("------------Fast Decryption----------------");
        long startMill3 = System.currentTimeMillis();
        BigInteger m2_recover = p.Fast_Decryption(em1);
        long endMill3 = System.currentTimeMillis();
        System.out.println("Fast Decryption Execution Time:" + String.valueOf(endMill3 - startMill3));
    }
}