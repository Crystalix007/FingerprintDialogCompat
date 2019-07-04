package com.kevalpatel2106.fingerprintdialog;

import android.annotation.TargetApi;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;

import java.io.Serializable;

/**
 * Created by Michael Kuc on 04/07/19.
 * Interface for generating the required crypto objects for authentication,
 * so client apps can re-use the ciphers involved
 *
 * @author <a href="https://github.com/Crystalix007">Crystalix007</a>
 */
public interface CryptoObjectGenerator extends Serializable {
    /**
     * Creates a new {@link android.hardware.fingerprint.FingerprintManager.CryptoObject} for authentication
     * @return {@link android.hardware.fingerprint.FingerprintManager.CryptoObject}
     */
    @TargetApi(Build.VERSION_CODES.M)
    FingerprintManager.CryptoObject getFingerprintCryptoObject();

    /**
     * Creates a new {@link android.hardware.biometrics.BiometricPrompt.CryptoObject}
     * @return {@link android.hardware.biometrics.BiometricPrompt.CryptoObject}
     */
    @TargetApi(Build.VERSION_CODES.P)
    BiometricPrompt.CryptoObject getBiometricCryptoObject();
}
