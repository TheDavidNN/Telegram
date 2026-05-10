package org.telegram.messenger;

import android.util.Log;

import org.telegram.tgnet.NativeByteBuffer;
import org.telegram.tgnet.TLObject;
import org.telegram.tgnet.TLRPC;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;

public class PerformanceTestAnamorphic {
    // static final int FIXED_PADDING_RANDOM = 62;
    static int nextPaddingRand = Utilities.random.nextInt(3); // FIXED_PADDING_RANDOM;

    static final int n = 5_000;
    static final String COVERT_MESSAGE = "A".repeat(29);
    private static final Pattern ANAMORPHIC_MSG_PATTERN = Pattern.compile("^.+\\(.+\\)$");


    private static void addRandomPadding(NativeByteBuffer buffer, int n) {
        byte[] b = new byte[n];
        Utilities.random.nextBytes(b);
        buffer.writeBytes(b);
    }

    private static int getPaddingLength(int len) {
        int extraLen = len % 16 != 0 ? 16 - len % 16 : 0; // { 0, 4, 8, 12}

        extraLen += (2 + nextPaddingRand) * 16; // adds element in { 32, 48, 64}
        nextPaddingRand =  Utilities.random.nextInt(3);

        int minNextBytes;
        if (nextPaddingRand == 0) {
            minNextBytes = 14;
        } else if (nextPaddingRand == 1) {
            minNextBytes = 29;
        } else {
            minNextBytes = 45;
        }

        int maxNextBytes = 29 + (nextPaddingRand * 16);

        return extraLen;
    }

    protected static void performSendEncryptedRequest(TLRPC.DecryptedMessage req, int layerUsed, boolean incoming, byte[] auth_key) {
        // Log.d("MyTest", "performSendEncryptedRequest 1");
        // Log.d("MyTest", req.message);

        /*
        if (req == null || chat.auth_key == null || chat instanceof TLRPC.TL_encryptedChatRequested || chat instanceof TLRPC.TL_encryptedChatWaiting) {
            return;
        }

         */

        // Log.d("MyTest", "performSendEncryptedRequest 2");

        boolean enableAnamorphicMessages = true;
        boolean isTextMessage = req instanceof TLRPC.TL_decryptedMessage;

        String msg = req.message;

        /*
            The allowed size of the anamorphic message partially depends on the length of the
            non-anamorphic message. The lengths are checked and validated later
         */
        String aMsg;

        if (isTextMessage && enableAnamorphicMessages) {
            if (ANAMORPHIC_MSG_PATTERN.matcher(msg).matches()) {
                String[] split = msg.split("\\(|\\)");

                msg = split[0];
                aMsg = split[1];

                // Log.d("MyTest", String.format("m  : %s", msg));
                // Log.d("MyTest", String.format("m' : %s", aMsg));
            } else {
                aMsg = null;
                // Log.d("MyTest", String.format("No match found for anamorphic message in string \"%s\"!", msg));
            }
        } else {
            aMsg = null;
        }
        req.message = msg;

        // getSendMessagesHelper().putToSendingMessages(newMsgObj, false);

        //Utilities.stageQueue.postRunnable(() -> {
        try {
            TLObject toEncryptObject;

            TLRPC.TL_decryptedMessageLayer layer = new TLRPC.TL_decryptedMessageLayer();

                /*
                int myLayer = Math.max(46, AndroidUtilities.getMyLayerVersion(chat.layer));
                layer.layer = Math.min(myLayer, Math.max(46, AndroidUtilities.getPeerLayerVersion(chat.layer)));
                 */
            layer.layer = layerUsed;

            layer.message = req;
            layer.random_bytes = new byte[15];

            int layerLen = layer.getObjectSize();
            int len = layerLen + 4;
            int extraLen = getPaddingLength(len);

            AnamorphicMessage anamorphicMessage = null;


            if (aMsg != null) {
                if (AnamorphicMessagingHelper.validAMsg(aMsg, extraLen - 1)) { // minus 1 to leave space for 1 byte of the IV
                    try {
                        anamorphicMessage = AnamorphicMessagingHelper.encrypt(aMsg, true);
                    } catch (Exception e) {
                        Log.d("MyTest", "Failed to encrypt aMsg");
                    }
                } else {
                    // invalid covert message
                    Log.d("MyTest", String.format("aMsg is invalid\naMsg is %d bytes\nextraLen - 1: %d", aMsg.getBytes(StandardCharsets.UTF_8).length, extraLen-1));
                }
            }

            if (anamorphicMessage != null) {
                // use the first 15 bytes of the iv as random bytes
                layer.random_bytes = Arrays.copyOfRange(anamorphicMessage.iv, 0, 15);
            } else {
                // use random bytes
                Utilities.random.nextBytes(layer.random_bytes);
            }

            toEncryptObject = layer;

            // Log.d("MyTest", String.format("layer.random_bytes.length: %d", layer.random_bytes.length));

                /*
                if (chat.seq_in == 0 && chat.seq_out == 0) {
                    if (chat.admin_id == getUserConfig().getClientUserId()) {
                        chat.seq_out = 1;
                        chat.seq_in = -2;
                    } else {
                        chat.seq_in = -1;
                    }
                }

                if (newMsgObj.seq_in == 0 && newMsgObj.seq_out == 0) {
                    layer.in_seq_no = chat.seq_in > 0 ? chat.seq_in : chat.seq_in + 2;
                    layer.out_seq_no = chat.seq_out;
                    chat.seq_out += 2;

                    if (chat.key_create_date == 0) {
                        chat.key_create_date = getConnectionsManager().getCurrentTime();
                    }
                    chat.key_use_count_out++;
                    Log.d("MyTest", String.format("chat.key_use_count_out: %d", chat.key_use_count_out));
                    if ((chat.key_use_count_out >= 100 || chat.key_create_date < getConnectionsManager().getCurrentTime() - 60 * 60 * 24 * 7) && chat.exchange_id == 0 && chat.future_key_fingerprint == 0) {
                        requestNewSecretChatKey(chat);
                    }

                    getMessagesStorage().updateEncryptedChatSeq(chat, false);
                    newMsgObj.seq_in = layer.in_seq_no;
                    newMsgObj.seq_out = layer.out_seq_no;
                    getMessagesStorage().setMessageSeq(newMsgObj.id, newMsgObj.seq_in, newMsgObj.seq_out);
                } else {
                    layer.in_seq_no = newMsgObj.seq_in;
                    layer.out_seq_no = newMsgObj.seq_out;
                }
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d(req + " send message with in_seq = " + layer.in_seq_no + " out_seq = " + layer.out_seq_no);
                }

                 */

            // Log.d("MyTest", String.format("Sending!\nlayer.out_seq_no: %d", layer.out_seq_no));

            // int len = toEncryptObject.getObjectSize();
            // Log.d("MyTest", String.format("toEncryptObject.getObjectSize(): %d", toEncryptObject.getObjectSize()));
            NativeByteBuffer toEncrypt = new NativeByteBuffer(4 + layerLen);
            toEncrypt.writeInt32(layerLen);
            toEncryptObject.serializeToStream(toEncrypt);


            NativeByteBuffer dataForEncryption = new NativeByteBuffer(len + extraLen);
            toEncrypt.position(0);
            dataForEncryption.writeBytes(toEncrypt);

            if (anamorphicMessage == null) {
                // Log.d("MyTest", "Send normal message!");
                addRandomPadding(dataForEncryption, extraLen);
            } else {
                int paddingNeeded = extraLen - 1 - anamorphicMessage.formattedCiphertext.length; // minus IV byte and ciphertext
                byte[] padding = new byte[paddingNeeded];
                Utilities.random.nextBytes(padding);

                        /*
                            remember, NativeByteBuffer.writeBytes(byte[] b) does not prepend b.length!
                            writing more data than there is space for in the buffer causes an exception to be thrown
                        */
                dataForEncryption.writeByte(anamorphicMessage.iv[15]);
                // Log.d("MyTest", String.format("Before adding ciphertext and padding: %d / %d", dataForEncryption.position(), dataForEncryption.limit()));
                dataForEncryption.writeBytes(anamorphicMessage.formattedCiphertext);
                // Log.d("MyTest", String.format("Between adding ciphertext and padding: %d / %d", dataForEncryption.position(), dataForEncryption.limit()));
                dataForEncryption.writeBytes(padding);
                // Log.d("MyTest", String.format("After adding ciphertext and padding: %d / %d", dataForEncryption.position(), dataForEncryption.limit()));

                    /*
                    Log.d("MyTest", String.format(
                            "Send anamorphic!\nciphertext: %s\niv: %s",
                            Arrays.toString(anamorphicMessage.formattedCiphertext),
                            Arrays.toString(anamorphicMessage.iv)
                    ));
                     */
            }

            byte[] messageKey = new byte[16];
            byte[] messageKeyFull;

            messageKeyFull = Utilities.computeSHA256(auth_key, 88 + (incoming ? 8 : 0), 32, dataForEncryption.buffer, 0, dataForEncryption.buffer.limit());
            System.arraycopy(messageKeyFull, 8, messageKey, 0, 16);

            toEncrypt.reuse();

            MessageKeyData keyData = MessageKeyData.generateMessageKeyData(auth_key, messageKey, incoming, 2);

            Utilities.aesIgeEncryption(dataForEncryption.buffer, keyData.aesKey, keyData.aesIv, true, false, 0, dataForEncryption.limit());

                /*
                NativeByteBuffer data = new NativeByteBuffer(8 + messageKey.length + dataForEncryption.length());
                dataForEncryption.position(0);
                data.writeInt64(chat.key_fingerprint);
                data.writeBytes(messageKey);
                data.writeBytes(dataForEncryption);
                dataForEncryption.reuse();

                data.position(0);

                 */
                /*
                TLObject reqToSend;

                if (encryptedFile == null) {
                    if (req instanceof TLRPC.TL_decryptedMessageService) {
                        TLRPC.TL_messages_sendEncryptedService req2 = new TLRPC.TL_messages_sendEncryptedService();
                        req2.data = data;
                        req2.random_id = req.random_id;
                        req2.peer = new TLRPC.TL_inputEncryptedChat();
                        req2.peer.chat_id = chat.id;
                        req2.peer.access_hash = chat.access_hash;
                        reqToSend = req2;
                    } else {
                        TLRPC.TL_messages_sendEncrypted req2 = new TLRPC.TL_messages_sendEncrypted();
                        req2.silent = newMsgObj.silent;
                        req2.data = data;
                        req2.random_id = req.random_id;
                        req2.peer = new TLRPC.TL_inputEncryptedChat();
                        req2.peer.chat_id = chat.id;
                        req2.peer.access_hash = chat.access_hash;
                        reqToSend = req2;
                    }
                } else {
                    TLRPC.TL_messages_sendEncryptedFile req2 = new TLRPC.TL_messages_sendEncryptedFile();
                    req2.silent = newMsgObj.silent;
                    req2.data = data;
                    req2.random_id = req.random_id;
                    req2.peer = new TLRPC.TL_inputEncryptedChat();
                    req2.peer.chat_id = chat.id;
                    req2.peer.access_hash = chat.access_hash;
                    req2.file = encryptedFile;
                    reqToSend = req2;
                }


                getConnectionsManager().sendRequest(reqToSend, (response, error) -> {
                    if (error == null) {
                        if (req.action instanceof TLRPC.TL_decryptedMessageActionNotifyLayer) {
                            TLRPC.EncryptedChat currentChat = getMessagesController().getEncryptedChat(chat.id);
                            if (currentChat == null) {
                                currentChat = chat;
                            }

                            if (currentChat.key_hash == null) {
                                currentChat.key_hash = AndroidUtilities.calcAuthKeyHash(currentChat.auth_key);
                            }

                            if (currentChat.key_hash.length == 16) {
                                try {
                                    byte[] sha256 = Utilities.computeSHA256(chat.auth_key, 0, chat.auth_key.length);
                                    byte[] key_hash = new byte[36];
                                    System.arraycopy(chat.key_hash, 0, key_hash, 0, 16);
                                    System.arraycopy(sha256, 0, key_hash, 16, 20);
                                    currentChat.key_hash = key_hash;
                                    getMessagesStorage().updateEncryptedChat(currentChat);
                                } catch (Throwable e) {
                                    FileLog.e(e);
                                }
                            }

                            sendingNotifyLayer.remove((Integer) currentChat.id);
                            currentChat.layer = AndroidUtilities.setMyLayerVersion(currentChat.layer, CURRENT_SECRET_CHAT_LAYER);
                            getMessagesStorage().updateEncryptedChatLayer(currentChat);
                        }
                    }
                    if (error == null) {
                        String attachPath = newMsgObj.attachPath;
                        TLRPC.messages_SentEncryptedMessage res = (TLRPC.messages_SentEncryptedMessage) response;
                        if (isSecretVisibleMessage(newMsgObj)) {
                            newMsgObj.date = res.date;
                        }
                        int existFlags;
                        if (newMsg != null && res.file instanceof TLRPC.TL_encryptedFile) {
                            updateMediaPaths(newMsg, res.file, req, originalPath);
                            existFlags = newMsg.getMediaExistanceFlags();
                        } else {
                            existFlags = 0;
                        }
                        getMessagesStorage().getStorageQueue().postRunnable(() -> {
                            if (isSecretInvisibleMessage(newMsgObj)) {
                                res.date = 0;
                            }
                            getMessagesStorage().updateMessageStateAndId(newMsgObj.random_id, 0, newMsgObj.id, newMsgObj.id, res.date, false, 0, 0);
                            AndroidUtilities.runOnUIThread(() -> {
                                newMsgObj.send_state = MessageObject.MESSAGE_SEND_STATE_SENT;
                                getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer, newMsgObj.id, newMsgObj.id, newMsgObj, newMsgObj.dialog_id, 0L, existFlags, false);
                                getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer2, newMsgObj.id, newMsgObj.id, newMsgObj, newMsgObj.dialog_id, 0L, existFlags, false);
                                getSendMessagesHelper().processSentMessage(newMsgObj.id);
                                getSendMessagesHelper().removeFromSendingMessages(newMsgObj.id, false);
                            });
                        });
                    } else {
                        getMessagesStorage().markMessageAsSendError(newMsgObj, 0);
                        AndroidUtilities.runOnUIThread(() -> {
                            newMsgObj.send_state = MessageObject.MESSAGE_SEND_STATE_SEND_ERROR;
                            getNotificationCenter().postNotificationName(NotificationCenter.messageSendError, newMsgObj.id);
                            getSendMessagesHelper().processSentMessage(newMsgObj.id);
                            getSendMessagesHelper().removeFromSendingMessages(newMsgObj.id, false);
                        });
                    }
                }, ConnectionsManager.RequestFlagInvokeAfter);

                */
        } catch (Exception e) {
            FileLog.e(e);
        }
        // });
    }

    protected static void performSendEncryptedRequest(TLRPC.DecryptedMessage req, String aMsg, int layerUsed, boolean incoming, byte[] auth_key) {
        // getSendMessagesHelper().putToSendingMessages(newMsgObj, false);

        // Utilities.stageQueue.postRunnable(() -> {
        try {
            TLObject toEncryptObject;

            TLRPC.TL_decryptedMessageLayer layer = new TLRPC.TL_decryptedMessageLayer();

                /*
                int myLayer = Math.max(46, AndroidUtilities.getMyLayerVersion(chat.layer));
                layer.layer = Math.min(myLayer, Math.max(46, AndroidUtilities.getPeerLayerVersion(chat.layer)));
                 */
            layer.layer = layerUsed;

            layer.message = req;
            layer.random_bytes = new byte[15];

            int layerLen = layer.getObjectSize();
            int len = layerLen + 4;
            int extraLen = getPaddingLength(len);

            AnamorphicMessage anamorphicMessage = null;


            if (aMsg != null) {
                if (AnamorphicMessagingHelper.validAMsg(aMsg, extraLen - 1)) { // minus 1 to leave space for 1 byte of the IV
                    try {
                        anamorphicMessage = AnamorphicMessagingHelper.encrypt(aMsg, true);
                    } catch (Exception e) {
                        // Log.d("MyTest", "Failed to encrypt aMsg");
                    }
                } else {
                    // invalid covert message
                    // Log.d("MyTest", "aMsg is invalid");
                }
            }

            if (anamorphicMessage != null) {
                // use the first 15 bytes of the iv as random bytes
                layer.random_bytes = Arrays.copyOfRange(anamorphicMessage.iv, 0, 15);
            } else {
                // use random bytes
                Utilities.random.nextBytes(layer.random_bytes);
            }

            toEncryptObject = layer;

            // Log.d("MyTest", String.format("layer.random_bytes.length: %d", layer.random_bytes.length));

                /*
                if (chat.seq_in == 0 && chat.seq_out == 0) {
                    if (chat.admin_id == getUserConfig().getClientUserId()) {
                        chat.seq_out = 1;
                        chat.seq_in = -2;
                    } else {
                        chat.seq_in = -1;
                    }
                }

                if (newMsgObj.seq_in == 0 && newMsgObj.seq_out == 0) {
                    layer.in_seq_no = chat.seq_in > 0 ? chat.seq_in : chat.seq_in + 2;
                    layer.out_seq_no = chat.seq_out;
                    chat.seq_out += 2;

                    if (chat.key_create_date == 0) {
                        chat.key_create_date = getConnectionsManager().getCurrentTime();
                    }
                    chat.key_use_count_out++;
                    Log.d("MyTest", String.format("chat.key_use_count_out: %d", chat.key_use_count_out));
                    if ((chat.key_use_count_out >= 100 || chat.key_create_date < getConnectionsManager().getCurrentTime() - 60 * 60 * 24 * 7) && chat.exchange_id == 0 && chat.future_key_fingerprint == 0) {
                        requestNewSecretChatKey(chat);
                    }

                    getMessagesStorage().updateEncryptedChatSeq(chat, false);
                    newMsgObj.seq_in = layer.in_seq_no;
                    newMsgObj.seq_out = layer.out_seq_no;
                    getMessagesStorage().setMessageSeq(newMsgObj.id, newMsgObj.seq_in, newMsgObj.seq_out);
                } else {
                    layer.in_seq_no = newMsgObj.seq_in;
                    layer.out_seq_no = newMsgObj.seq_out;
                }
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d(req + " send message with in_seq = " + layer.in_seq_no + " out_seq = " + layer.out_seq_no);
                }

                 */

                /*
                Log.d("MyTest", String.format(
                        "Sending!\nlayer.out_seq_no: %d",
                        layer.out_seq_no
                ));

                 */

            // int len = toEncryptObject.getObjectSize();
            // Log.d("MyTest", String.format("toEncryptObject.getObjectSize(): %d", toEncryptObject.getObjectSize()));
            NativeByteBuffer toEncrypt = new NativeByteBuffer(4 + layerLen);
            toEncrypt.writeInt32(layerLen);
            toEncryptObject.serializeToStream(toEncrypt);


            NativeByteBuffer dataForEncryption = new NativeByteBuffer(len + extraLen);
            toEncrypt.position(0);
            dataForEncryption.writeBytes(toEncrypt);

            if (anamorphicMessage == null) {
                // Log.d("MyTest", "Send normal message!");
                addRandomPadding(dataForEncryption, extraLen);
            } else {
                int paddingNeeded = extraLen - 1 - anamorphicMessage.formattedCiphertext.length; // minus IV byte and ciphertext
                byte[] padding = new byte[paddingNeeded];
                Utilities.random.nextBytes(padding);

                        /*
                            remember, NativeByteBuffer.writeBytes(byte[] b) does not prepend b.length!
                            writing more data than there is space for in the buffer causes an exception to be thrown
                        */
                dataForEncryption.writeByte(anamorphicMessage.iv[15]);
                // Log.d("MyTest", String.format("Before adding ciphertext and padding: %d / %d", dataForEncryption.position(), dataForEncryption.limit()));
                dataForEncryption.writeBytes(anamorphicMessage.formattedCiphertext);
                // Log.d("MyTest", String.format("Between adding ciphertext and padding: %d / %d", dataForEncryption.position(), dataForEncryption.limit()));
                dataForEncryption.writeBytes(padding);
                // Log.d("MyTest", String.format("After adding ciphertext and padding: %d / %d", dataForEncryption.position(), dataForEncryption.limit()));

                    /*
                    Log.d("MyTest", String.format(
                            "Send anamorphic!\nciphertext: %s\niv: %s",
                            Arrays.toString(anamorphicMessage.formattedCiphertext),
                            Arrays.toString(anamorphicMessage.iv)
                    ));

                     */
            }

            byte[] messageKey = new byte[16];
            byte[] messageKeyFull;

            messageKeyFull = Utilities.computeSHA256(auth_key, 88 + (incoming ? 8 : 0), 32, dataForEncryption.buffer, 0, dataForEncryption.buffer.limit());
            System.arraycopy(messageKeyFull, 8, messageKey, 0, 16);

            toEncrypt.reuse();

            MessageKeyData keyData = MessageKeyData.generateMessageKeyData(auth_key, messageKey, incoming, 2);

            Utilities.aesIgeEncryption(dataForEncryption.buffer, keyData.aesKey, keyData.aesIv, true, false, 0, dataForEncryption.limit());

                /*
                NativeByteBuffer data = new NativeByteBuffer(8 + messageKey.length + dataForEncryption.length());
                dataForEncryption.position(0);
                data.writeInt64(chat.key_fingerprint);
                data.writeBytes(messageKey);
                data.writeBytes(dataForEncryption);
                dataForEncryption.reuse();

                data.position(0);

                 */
                /*
                TLObject reqToSend;

                if (encryptedFile == null) {
                    if (req instanceof TLRPC.TL_decryptedMessageService) {
                        TLRPC.TL_messages_sendEncryptedService req2 = new TLRPC.TL_messages_sendEncryptedService();
                        req2.data = data;
                        req2.random_id = req.random_id;
                        req2.peer = new TLRPC.TL_inputEncryptedChat();
                        req2.peer.chat_id = chat.id;
                        req2.peer.access_hash = chat.access_hash;
                        reqToSend = req2;
                    } else {
                        TLRPC.TL_messages_sendEncrypted req2 = new TLRPC.TL_messages_sendEncrypted();
                        req2.silent = newMsgObj.silent;
                        req2.data = data;
                        req2.random_id = req.random_id;
                        req2.peer = new TLRPC.TL_inputEncryptedChat();
                        req2.peer.chat_id = chat.id;
                        req2.peer.access_hash = chat.access_hash;
                        reqToSend = req2;
                    }
                } else {
                    TLRPC.TL_messages_sendEncryptedFile req2 = new TLRPC.TL_messages_sendEncryptedFile();
                    req2.silent = newMsgObj.silent;
                    req2.data = data;
                    req2.random_id = req.random_id;
                    req2.peer = new TLRPC.TL_inputEncryptedChat();
                    req2.peer.chat_id = chat.id;
                    req2.peer.access_hash = chat.access_hash;
                    req2.file = encryptedFile;
                    reqToSend = req2;
                }


                getConnectionsManager().sendRequest(reqToSend, (response, error) -> {
                    if (error == null) {
                        if (req.action instanceof TLRPC.TL_decryptedMessageActionNotifyLayer) {
                            TLRPC.EncryptedChat currentChat = getMessagesController().getEncryptedChat(chat.id);
                            if (currentChat == null) {
                                currentChat = chat;
                            }

                            if (currentChat.key_hash == null) {
                                currentChat.key_hash = AndroidUtilities.calcAuthKeyHash(currentChat.auth_key);
                            }

                            if (currentChat.key_hash.length == 16) {
                                try {
                                    byte[] sha256 = Utilities.computeSHA256(chat.auth_key, 0, chat.auth_key.length);
                                    byte[] key_hash = new byte[36];
                                    System.arraycopy(chat.key_hash, 0, key_hash, 0, 16);
                                    System.arraycopy(sha256, 0, key_hash, 16, 20);
                                    currentChat.key_hash = key_hash;
                                    getMessagesStorage().updateEncryptedChat(currentChat);
                                } catch (Throwable e) {
                                    FileLog.e(e);
                                }
                            }

                            sendingNotifyLayer.remove((Integer) currentChat.id);
                            currentChat.layer = AndroidUtilities.setMyLayerVersion(currentChat.layer, CURRENT_SECRET_CHAT_LAYER);
                            getMessagesStorage().updateEncryptedChatLayer(currentChat);
                        }
                    }
                    if (error == null) {
                        String attachPath = newMsgObj.attachPath;
                        TLRPC.messages_SentEncryptedMessage res = (TLRPC.messages_SentEncryptedMessage) response;
                        if (isSecretVisibleMessage(newMsgObj)) {
                            newMsgObj.date = res.date;
                        }
                        int existFlags;
                        if (newMsg != null && res.file instanceof TLRPC.TL_encryptedFile) {
                            updateMediaPaths(newMsg, res.file, req, originalPath);
                            existFlags = newMsg.getMediaExistanceFlags();
                        } else {
                            existFlags = 0;
                        }
                        getMessagesStorage().getStorageQueue().postRunnable(() -> {
                            if (isSecretInvisibleMessage(newMsgObj)) {
                                res.date = 0;
                            }
                            getMessagesStorage().updateMessageStateAndId(newMsgObj.random_id, 0, newMsgObj.id, newMsgObj.id, res.date, false, 0, 0);
                            AndroidUtilities.runOnUIThread(() -> {
                                newMsgObj.send_state = MessageObject.MESSAGE_SEND_STATE_SENT;
                                getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer, newMsgObj.id, newMsgObj.id, newMsgObj, newMsgObj.dialog_id, 0L, existFlags, false);
                                getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer2, newMsgObj.id, newMsgObj.id, newMsgObj, newMsgObj.dialog_id, 0L, existFlags, false);
                                getSendMessagesHelper().processSentMessage(newMsgObj.id);
                                getSendMessagesHelper().removeFromSendingMessages(newMsgObj.id, false);
                            });
                        });
                    } else {
                        getMessagesStorage().markMessageAsSendError(newMsgObj, 0);
                        AndroidUtilities.runOnUIThread(() -> {
                            newMsgObj.send_state = MessageObject.MESSAGE_SEND_STATE_SEND_ERROR;
                            getNotificationCenter().postNotificationName(NotificationCenter.messageSendError, newMsgObj.id);
                            getSendMessagesHelper().processSentMessage(newMsgObj.id);
                            getSendMessagesHelper().removeFromSendingMessages(newMsgObj.id, false);
                        });
                    }
                }, ConnectionsManager.RequestFlagInvokeAfter);

                */
        } catch (Exception e) {
            FileLog.e(e);
        }
        // });
    }


    public static void test(TLRPC.DecryptedMessage req) {
        Utilities.stageQueue.postRunnable(() -> {
            byte[] auth_key = new byte[256];
            String msg = req.message;
            Utilities.random.nextBytes(auth_key);

            long startTime;
            long endTime;

            System.gc();
            {
                startTime = System.currentTimeMillis();
                for (int i = 0; i < n; i++) {
                    performSendEncryptedRequest(req, 217, false, auth_key);
                }
                endTime = System.currentTimeMillis();
                Log.d("MyTest", String.format("Anamorphic, regex, without covert message time: %d", endTime - startTime));
            }

            System.gc();

            {
                String aMsg = String.format("%s (%s)", req.message, COVERT_MESSAGE);
                startTime = System.currentTimeMillis();
                for (int i = 0; i < n; i++) {
                    req.message = aMsg;
                    performSendEncryptedRequest(req, 217, false, auth_key);
                }
                endTime = System.currentTimeMillis();
                Log.d("MyTest", String.format("Anamorphic, regex, with covert message time: %d", endTime - startTime));
            }
            System.gc();

            req.message = msg;
            {
                startTime = System.currentTimeMillis();
                for (int i = 0; i < n; i++) {
                    performSendEncryptedRequest(req, null, 217, false, auth_key);
                }
                endTime = System.currentTimeMillis();
                Log.d("MyTest", String.format("Anamorphic, no regex, without covert message time: %d", endTime - startTime));
            }

            System.gc();

            {
                startTime = System.currentTimeMillis();
                for (int i = 0; i < n; i++) {
                    performSendEncryptedRequest(req, COVERT_MESSAGE, 217, false, auth_key);
                }
                endTime = System.currentTimeMillis();
                Log.d("MyTest", String.format("Anamorphic, no regex, with covert message time: %d", endTime - startTime));
            }

            System.gc();

            req.message = msg;
        });
    }
}