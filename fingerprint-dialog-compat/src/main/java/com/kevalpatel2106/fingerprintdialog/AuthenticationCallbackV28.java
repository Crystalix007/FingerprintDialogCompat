/*
 * Copyright 2018 Keval Patel
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance wit
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
 *  the specific language governing permissions and limitations under the License.
 */

package com.kevalpatel2106.fingerprintdialog;

import android.annotation.TargetApi;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import androidx.annotation.NonNull;

/**
 * Created by Keval on 08/04/18.
 * This class converts {@link BiometricPrompt.AuthenticationCallback} into {@link AuthenticationCallback}
 * for the android version P and above.
 *
 * @author <a href="https://github.com/kevalpatel2106">kevalpatel2106</a>
 */
@TargetApi(Build.VERSION_CODES.P)
class AuthenticationCallbackV28 extends BiometricPrompt.AuthenticationCallback {

    /**
     * {@link AuthenticationCallback} implemented by the caller.
     */
    @NonNull
    private final AuthenticationCallback mCallback;

    /**
     * Public constructor.
     *
     * @param authenticationCallback {@link AuthenticationCallback} get fire appropriate events for
     *                               the fingerprint authentication.
     */
    AuthenticationCallbackV28(@NonNull final AuthenticationCallback authenticationCallback) {
        mCallback = authenticationCallback;
    }

    /**
     * @see BiometricPrompt.AuthenticationCallback#onAuthenticationError(int, CharSequence)
     */
    @Override
    public void onAuthenticationError(final int errorCode, final CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);

        switch (errorCode) {

            //User canceled the scanning process by pressing the negative button.
            case BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED:
                mCallback.authenticationCanceledByUser();
                break;

            // Device doesn't have the supported fingerprint hardware.
            case  BiometricPrompt.BIOMETRIC_ERROR_HW_NOT_PRESENT:
            case BiometricPrompt.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                mCallback.fingerprintAuthenticationNotSupported();
                break;

            //User did not register any fingerprints.
            case BiometricPrompt.BIOMETRIC_ERROR_NO_BIOMETRICS:
                mCallback.hasNoFingerprintEnrolled();
                break;

                //Any other unrecoverable error
            default:
                mCallback.onAuthenticationError(errorCode, errString);
        }
    }


    /**
     * @see BiometricPrompt.AuthenticationCallback#onAuthenticationFailed()
     */
    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
        mCallback.onAuthenticationFailed();
    }

    /**
     * @see BiometricPrompt.AuthenticationCallback#onAuthenticationHelp(int, CharSequence)
     */
    @Override
    public void onAuthenticationHelp(final int helpCode, final CharSequence helpString) {
        super.onAuthenticationHelp(helpCode, helpString);
        mCallback.onAuthenticationHelp(helpCode, helpString);
    }

    /**
     * @see BiometricPrompt.AuthenticationCallback#onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult)
     */
    @Override
    public void onAuthenticationSucceeded(final BiometricPrompt.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        mCallback.onAuthenticationSucceeded();
    }
}
