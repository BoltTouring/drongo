package com.sparrowwallet.drongo.nip05;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import static com.sparrowwallet.drongo.protocol.ScriptType.P2TR;

/**
 * Verifies Silent Payment notifications against the blockchain and derives spending keys.
 *
 * Given a notification (txid, vout, amount) and the recipient's SP scan/spend keys,
 * this class can:
 * 1. Verify the output exists and matches the expected amount
 * 2. Derive the spending private key so the UTXO can be spent
 *
 * This is the receiver-side counterpart to SilentPaymentUtils.computeOutputAddresses().
 */
public class SpNotificationVerifier {
    private static final Logger log = LoggerFactory.getLogger(SpNotificationVerifier.class);

    /**
     * Result of verifying an SP notification.
     */
    public record VerificationResult(
            boolean verified,
            String error,
            Address outputAddress,
            long confirmedAmount,
            int blockHeight,
            ECKey spendingPrivateKey
    ) {
        public static VerificationResult success(Address address, long amount, int height, ECKey spendingKey) {
            return new VerificationResult(true, null, address, amount, height, spendingKey);
        }

        public static VerificationResult failure(String error) {
            return new VerificationResult(false, error, null, 0, 0, null);
        }
    }

    /**
     * Verify a Silent Payment notification and derive the spending key.
     *
     * @param notification the SP notification (txid, vout, amount)
     * @param transaction the full transaction (fetched from Electrum)
     * @param spentScriptPubKeys map of input outpoints → their scriptPubKeys (fetched from Electrum)
     * @param scanPrivateKey the recipient's BIP 352 scan private key
     * @param spendPrivateKey the recipient's BIP 352 spend private key
     * @return verification result with spending key if successful
     */
    public static VerificationResult verify(
            SilentPaymentNotification notification,
            Transaction transaction,
            Map<HashIndex, Script> spentScriptPubKeys,
            ECKey scanPrivateKey,
            ECKey spendPrivateKey) {

        try {
            // Validate transaction ID matches
            String txid = transaction.getTxId().toString();
            if(!txid.equals(notification.txid())) {
                return VerificationResult.failure("Transaction ID mismatch");
            }

            // Validate vout is in range
            int vout = notification.vout();
            if(vout < 0 || vout >= transaction.getOutputs().size()) {
                return VerificationResult.failure("Output index " + vout + " out of range (tx has " + transaction.getOutputs().size() + " outputs)");
            }

            // Check the output is P2TR
            TransactionOutput output = transaction.getOutputs().get(vout);
            if(!P2TR.isScriptType(output.getScript())) {
                return VerificationResult.failure("Output " + vout + " is not P2TR (Taproot)");
            }

            // Verify amount matches
            if(output.getValue() != notification.amount()) {
                return VerificationResult.failure("Amount mismatch: notification says " + notification.amount() + " but output has " + output.getValue());
            }

            // Get the actual output key from the transaction
            ECKey outputKey = P2TR.getPublicKeyFromScript(output.getScript());
            Address outputAddress = P2TR.getAddress(outputKey.getPubKeyXCoord());
            log.info("SP Verify: output address = " + outputAddress);

            // Compute the tweak from transaction inputs
            byte[] tweakBytes = SilentPaymentUtils.getTweak(transaction, spentScriptPubKeys);
            if(tweakBytes == null) {
                return VerificationResult.failure("Could not compute tweak from transaction inputs");
            }
            ECKey tweak = ECKey.fromPublicOnly(tweakBytes);

            // Receiver-side computation:
            // shared_secret = scan_priv * tweak (where tweak = A_sum * input_hash)
            ECKey sharedSecret = tweak.multiply(scanPrivateKey.getPrivKey(), true);

            // t_0 = tagged_hash("BIP0352/SharedSecret", shared_secret || 0)
            byte[] t0Bytes = Utils.taggedHash(SilentPaymentUtils.BIP_0352_SHARED_SECRET_TAG,
                    Utils.concat(sharedSecret.getPubKey(true),
                            ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(0).array()));
            BigInteger t0 = new BigInteger(1, t0Bytes);

            // Check t0 is valid
            if(t0.equals(BigInteger.ZERO) || t0.compareTo(ECKey.CURVE.getCurve().getOrder()) >= 0) {
                return VerificationResult.failure("Invalid tweak value");
            }

            // Expected output key = spend_pub + t0 * G
            ECKey spendPubKey = ECKey.fromPublicOnly(spendPrivateKey);
            ECKey t0Point = ECKey.fromPublicOnly(ECKey.publicPointFromPrivate(t0).getEncoded(true));
            ECKey expectedKey = spendPubKey.add(t0Point, true);
            Address expectedAddress = P2TR.getAddress(expectedKey.getPubKeyXCoord());
            log.info("SP Verify: expected address = " + expectedAddress);

            // Verify the output matches
            if(!outputAddress.equals(expectedAddress)) {
                return VerificationResult.failure("Output address does not match expected SP-derived address. Got " +
                        outputAddress + ", expected " + expectedAddress);
            }

            // Derive spending private key = spend_priv + t0
            ECKey spendingKey = spendPrivateKey.addPrivate(ECKey.fromPrivate(t0));
            log.info("SP Verify: verification SUCCESS — derived spending key");

            return VerificationResult.success(outputAddress, output.getValue(), 0, spendingKey);
        } catch(Exception e) {
            log.error("SP Verify: exception during verification", e);
            return VerificationResult.failure("Verification error: " + e.getMessage());
        }
    }

    /**
     * Simple on-chain verification without SP key derivation.
     * Just checks the transaction exists and the output matches.
     *
     * @param notification the SP notification
     * @param transaction the fetched transaction
     * @return verification result (without spending key)
     */
    public static VerificationResult verifyBasic(SilentPaymentNotification notification, Transaction transaction) {
        try {
            String txid = transaction.getTxId().toString();
            if(!txid.equals(notification.txid())) {
                return VerificationResult.failure("Transaction ID mismatch");
            }

            int vout = notification.vout();
            if(vout < 0 || vout >= transaction.getOutputs().size()) {
                return VerificationResult.failure("Output index out of range");
            }

            TransactionOutput output = transaction.getOutputs().get(vout);
            if(output.getValue() != notification.amount()) {
                return VerificationResult.failure("Amount mismatch: expected " + notification.amount() + ", got " + output.getValue());
            }

            Address outputAddress = output.getScript().getToAddress();
            return VerificationResult.success(outputAddress, output.getValue(), 0, null);
        } catch(Exception e) {
            return VerificationResult.failure("Verification error: " + e.getMessage());
        }
    }
}
