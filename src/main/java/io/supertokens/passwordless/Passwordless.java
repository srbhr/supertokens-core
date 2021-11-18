/*
 *    Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
 *
 *    This software is licensed under the Apache License, Version 2.0 (the
 *    "License") as published by the Apache Software Foundation.
 *
 *    You may not use this file except in compliance with the License. You may
 *    obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 */

package io.supertokens.passwordless;

import io.supertokens.Main;
import io.supertokens.config.Config;
import io.supertokens.passwordless.exceptions.IncorrectUserInputCodeException;
import io.supertokens.passwordless.exceptions.RestartFlowException;
import io.supertokens.pluginInterface.emailpassword.exceptions.DuplicateEmailException;
import io.supertokens.pluginInterface.emailpassword.exceptions.DuplicateUserIdException;
import io.supertokens.pluginInterface.exceptions.StorageQueryException;
import io.supertokens.pluginInterface.exceptions.StorageTransactionLogicException;
import io.supertokens.pluginInterface.passwordless.PasswordlessCode;
import io.supertokens.pluginInterface.passwordless.PasswordlessDevice;
import io.supertokens.pluginInterface.passwordless.UserInfo;
import io.supertokens.pluginInterface.passwordless.exception.DuplicateCodeIdException;
import io.supertokens.pluginInterface.passwordless.exception.DuplicateDeviceIdHashException;
import io.supertokens.pluginInterface.passwordless.exception.DuplicateLinkCodeHashException;
import io.supertokens.pluginInterface.passwordless.exception.DuplicatePhoneNumberException;
import io.supertokens.pluginInterface.passwordless.exception.UnknownDeviceIdHash;
import io.supertokens.pluginInterface.passwordless.sqlStorage.PasswordlessSQLStorage;
import io.supertokens.storageLayer.StorageLayer;
import io.supertokens.utils.Utils;
import io.supertokens.webserver.WebserverAPI;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.ServletException;

import org.apache.tomcat.util.codec.binary.Base64;

public class Passwordless {
    private static final String USER_INPUT_CODE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private static Character getRandomAlphaChar(SecureRandom generator) {
        return USER_INPUT_CODE_ALPHABET.charAt(generator.nextInt(52));
    }

    private static Character getRandomNumChar(SecureRandom gen) {
        return Character.toChars(gen.nextInt(9) + 48)[0];
    }

    public static UserInfo getUserByPhoneNumber(Main main, String phoneNumber) throws StorageQueryException {
        return StorageLayer.getPasswordlessStorage(main).getUserByPhoneNumber(phoneNumber);
    }

    public static UserInfo getUserByEmail(Main main, String email) throws StorageQueryException {
        return StorageLayer.getPasswordlessStorage(main).getUserByEmail(email);
    }

    public static UserInfo getUserById(Main main, String userId) throws StorageQueryException {
        return StorageLayer.getPasswordlessStorage(main).getUserById(userId);
    }

    public static CreateCodeResponse createCode(Main main, String email, String phoneNumber, String deviceId,
            @Nullable String userInputCode) throws RestartFlowException, DuplicateLinkCodeHashException,
            StorageQueryException, NoSuchAlgorithmException, InvalidKeyException {
        PasswordlessSQLStorage passwordlessStorage = StorageLayer.getPasswordlessStorage(main);

        boolean gotDeviceId = deviceId != null;
        boolean gotUserInputCode = userInputCode != null;

        if (userInputCode == null) {
            userInputCode = generateUserInputCode();
        }

        byte[] deviceIdBytes = new byte[32];
        String deviceIdHash = null;
        if (gotDeviceId) {
            deviceIdBytes = Base64.decodeBase64(deviceId);
            deviceIdHash = Base64.encodeBase64URLSafeString(Utils.hashSHA256Bytes(deviceIdBytes));
            PasswordlessDevice device = passwordlessStorage.getDevice(deviceIdHash);
            if (device == null) {
                throw new RestartFlowException();
            }
        }

        SecureRandom generator = new SecureRandom();
        while (true) {
            if (!gotDeviceId) {
                generator.nextBytes(deviceIdBytes);
                deviceId = Base64.encodeBase64String(deviceIdBytes);
                deviceIdHash = Base64.encodeBase64URLSafeString(Utils.hashSHA256Bytes(deviceIdBytes));
            }
            String codeId = Utils.getUUID();

            byte[] linkCodeBytes = Utils.hmacSHA256(deviceIdBytes, userInputCode);
            byte[] linkCodeHashBytes = Utils.hashSHA256Bytes(linkCodeBytes);

            String linkCode = Base64.encodeBase64URLSafeString(linkCodeBytes);
            String linkCodeHash = Base64.encodeBase64String(linkCodeHashBytes);

            long createdAt = System.currentTimeMillis();

            final String currDeviceIdHash = deviceIdHash;
            try {
                passwordlessStorage.startTransaction(con -> {
                    if (!gotDeviceId) {
                        try {
                            passwordlessStorage.createDevice_Transaction(con, currDeviceIdHash, email, phoneNumber);
                        } catch (DuplicateDeviceIdHashException ex) {
                            throw new StorageTransactionLogicException(ex);
                        }
                    } else {
                        PasswordlessDevice device = passwordlessStorage.getDevice_Transaction(con, currDeviceIdHash);
                        if (device == null) {
                            throw new StorageTransactionLogicException(new UnknownDeviceIdHash());
                        }
                    }

                    try {
                        passwordlessStorage.createCode_Transaction(con, codeId, currDeviceIdHash, linkCodeHash,
                                createdAt);
                    } catch (UnknownDeviceIdHash | DuplicateCodeIdException | DuplicateLinkCodeHashException ex) {
                        throw new StorageTransactionLogicException(ex);
                    }
                    passwordlessStorage.commitTransaction(con);
                    return null;
                });
            } catch (StorageTransactionLogicException e) {
                if (e.actualException instanceof DuplicateLinkCodeHashException) {
                    // We only need to rethrow if the user supplied both the deviceId and the userInputCode,
                    // because in that case the linkCodeHash will always be the same.
                    if (gotDeviceId && gotUserInputCode) {
                        throw (DuplicateLinkCodeHashException) e.actualException;
                    }
                } else if (e.actualException instanceof UnknownDeviceIdHash) {
                    throw new RestartFlowException();
                }
                // We could also get: DuplicateCodeIdException, DuplicateDeviceIdHashException
                // These are retryable, so ignored here.
            }

            return new CreateCodeResponse(deviceIdHash, codeId, deviceId, userInputCode, linkCode, createdAt);
        }
    }

    private static String generateUserInputCode() {
        SecureRandom generator = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        int prevAlphaCharCount = 0;
        for (int i = 0; i < 6; ++i) {
            if ((i < 2 || prevAlphaCharCount < 2) && generator.nextBoolean()) {
                ++prevAlphaCharCount;
                sb.append(getRandomAlphaChar(generator));
            } else {
                prevAlphaCharCount = 0;
                sb.append(getRandomNumChar(generator));
            }
        }
        return sb.toString();
    }

    public static PasswordlessDevice[] listDevicesByEmail(Main main, String email) throws StorageQueryException {
        PasswordlessSQLStorage passwordlessStorage = StorageLayer.getPasswordlessStorage(main);
        return passwordlessStorage.getDevicesByEmail(email);
    }

    public static PasswordlessDevice[] listDevicesByPhoneNumber(Main main, String phoneNumber)
            throws StorageQueryException {
        PasswordlessSQLStorage passwordlessStorage = StorageLayer.getPasswordlessStorage(main);
        return passwordlessStorage.getDevicesByPhoneNumber(phoneNumber);
    }

    public static PasswordlessCode[] listCodesOfDevice(Main main, String deviceId) throws StorageQueryException {
        PasswordlessSQLStorage passwordlessStorage = StorageLayer.getPasswordlessStorage(main);
        return passwordlessStorage.getCodesOfDevice(deviceId);
    }

    public static ConsumeCodeResponse consumeCode(Main main, String deviceId, String userInputCode, String linkCode)
            throws Exception, NoSuchAlgorithmException, InvalidKeyException {
        PasswordlessSQLStorage passwordlessStorage = StorageLayer.getPasswordlessStorage(main);
        long passwordlessCodeLifetime = Config.getConfig(main).getPasswordlessCodeLifetime();
        String deviceIdHash;
        String linkCodeHash;
        if (linkCode != null) {
            byte[] linkCodeBytes = Base64.decodeBase64URLSafe(linkCode);
            byte[] linkCodeHashBytes = Utils.hashSHA256Bytes(linkCodeBytes);
            linkCodeHash = Base64.encodeBase64String(linkCodeHashBytes);
            PasswordlessCode code = passwordlessStorage.getCodeByLinkCodeHash(linkCodeHash);
            if (code == null || code.createdAt < System.currentTimeMillis() - passwordlessCodeLifetime) {
                throw new RestartFlowException();
            }
            deviceIdHash = code.deviceIdHash;
        } else {
            byte[] deviceIdBytes = Base64.decodeBase64(deviceId);
            deviceIdHash = Base64.encodeBase64URLSafeString(Utils.hashSHA256Bytes(deviceIdBytes));

            byte[] linkCodeBytes = Utils.hmacSHA256(deviceIdBytes, userInputCode);
            byte[] linkCodeHashBytes = Utils.hashSHA256Bytes(linkCodeBytes);
            linkCodeHash = Base64.encodeBase64String(linkCodeHashBytes);
        }

        while (true) {
            try {
                return passwordlessStorage.startTransaction(con -> {
                    PasswordlessDevice device = passwordlessStorage.getDevice_Transaction(con, deviceIdHash);
                    if (device == null) {
                        throw new StorageTransactionLogicException(new RestartFlowException());
                    }
                    if (device.failedAttempts >= Config.getConfig(main).getAccessTokenValidity()) {
                        passwordlessStorage.deleteDevice_Transaction(con, deviceIdHash);
                        passwordlessStorage.commitTransaction(con);
                        throw new StorageTransactionLogicException(new RestartFlowException());
                    }
                    PasswordlessCode code = passwordlessStorage.getCodeByLinkCodeHash_Transaction(con, linkCodeHash);
                    if (code == null || code.createdAt < System.currentTimeMillis() - passwordlessCodeLifetime) {
                        if (deviceId != null) {
                            if (device.failedAttempts + 1 == Config.getConfig(main)
                                    .getPasswordlessMaxCodeInputAttempts()) {
                                passwordlessStorage.deleteDevice_Transaction(con, deviceIdHash);
                                passwordlessStorage.commitTransaction(con);
                                throw new StorageTransactionLogicException(new RestartFlowException());
                            } else {
                                PasswordlessCode[] codes = passwordlessStorage.getCodesOfDevice_Transaction(con,
                                        deviceIdHash);
                                if (Arrays.stream(codes)
                                        .anyMatch(otherCode -> otherCode.createdAt > System.currentTimeMillis()
                                                - passwordlessCodeLifetime)) {
                                    passwordlessStorage.incrementDeviceFailedAttemptCount_Transaction(con,
                                            deviceIdHash);
                                    passwordlessStorage.commitTransaction(con);
                                } else {
                                    passwordlessStorage.deleteDevice_Transaction(con, deviceIdHash);
                                    passwordlessStorage.commitTransaction(con);
                                    throw new StorageTransactionLogicException(new RestartFlowException());
                                }
                                throw new StorageTransactionLogicException(
                                        new IncorrectUserInputCodeException(device.failedAttempts + 1));
                            }
                        }
                        throw new StorageTransactionLogicException(new RestartFlowException());
                    }

                    // Code exists and is valid
                    UserInfo user = device.email != null ? passwordlessStorage.getUserByEmail(device.email)
                            : passwordlessStorage.getUserByPhoneNumber(device.phoneNumber);

                    if (user == null) {
                        String userId = Utils.getUUID();
                        long timeJoined = System.currentTimeMillis();
                        if (device.email != null) {
                            passwordlessStorage.deleteDevicesByEmail_Transaction(con, device.email);
                        } else if (device.phoneNumber != null) {
                            passwordlessStorage.deleteDevicesByPhoneNumber_Transaction(con, device.phoneNumber);
                        }

                        try {
                            passwordlessStorage.createUser_Transaction(con, userId, device.email, device.phoneNumber,
                                    timeJoined);
                        } catch (DuplicateUserIdException | DuplicateEmailException
                                | DuplicatePhoneNumberException ex) {
                            throw new StorageTransactionLogicException(ex);
                        }
                        return new ConsumeCodeResponse(true,
                                new UserInfo(userId, device.email, device.phoneNumber, timeJoined));
                    } else {
                        if (user.email != null) {
                            passwordlessStorage.deleteDevicesByEmail_Transaction(con, user.email);
                        }
                        if (user.phoneNumber != null) {
                            passwordlessStorage.deleteDevicesByPhoneNumber_Transaction(con, user.phoneNumber);
                        }
                        passwordlessStorage.commitTransaction(con);
                        return new ConsumeCodeResponse(false, user);
                    }
                });
            } catch (StorageTransactionLogicException e) {
                if (e.actualException instanceof DuplicateUserIdException) {
                    continue;
                } else if (e.actualException instanceof DuplicateEmailException
                        || e.actualException instanceof DuplicatePhoneNumberException) {
                    // This should never actually get here:
                    // We could only get here if someone used two different codes at the same time for their first
                    // login,
                    // but this should end up as a deadlock because they both locked their own devices
                    // and tried to delete all other devices with the same email/phoneNumber
                    throw e.actualException;
                }
                throw e.actualException;
            }
        }
    }

    public static class CreateCodeResponse {
        public String deviceIdHash;
        public String codeId;
        public String deviceId;
        public String userInputCode;
        public String linkCode;
        public long timeCreated;

        public CreateCodeResponse(String deviceIdHash, String codeId, String deviceId, String userInputCode,
                String linkCode, long timeCreated) {
            this.deviceIdHash = deviceIdHash;
            this.codeId = codeId;
            this.deviceId = deviceId;
            this.userInputCode = userInputCode;
            this.linkCode = linkCode;
            this.timeCreated = timeCreated;
        }
    }

    public static class ConsumeCodeResponse {
        public boolean createdNewUser;
        public UserInfo user;

        public ConsumeCodeResponse(boolean createdNewUser, UserInfo user) {
            this.createdNewUser = createdNewUser;
            this.user = user;
        }
    }
}
