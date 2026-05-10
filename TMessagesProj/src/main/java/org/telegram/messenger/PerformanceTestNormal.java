package org.telegram.messenger;

import android.util.Log;

import org.telegram.tgnet.NativeByteBuffer;
import org.telegram.tgnet.TLObject;
import org.telegram.tgnet.TLRPC;


public class PerformanceTestNormal {
    static final int n = 5_000;

    private static void performSendEncryptedRequest(TLRPC.DecryptedMessage req, int layerUsed, boolean incoming, byte[] auth_key) {


        /*
        if (req == null || chat.auth_key == null || chat instanceof TLRPC.TL_encryptedChatRequested || chat instanceof TLRPC.TL_encryptedChatWaiting) {
            return;
        }

        */

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
            Utilities.random.nextBytes(layer.random_bytes);
            toEncryptObject = layer;

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

            int len = toEncryptObject.getObjectSize();
            NativeByteBuffer toEncrypt = new NativeByteBuffer(4 + len);
            toEncrypt.writeInt32(len);
            toEncryptObject.serializeToStream(toEncrypt);

            len = toEncrypt.length();
            int extraLen = len % 16 != 0 ? 16 - len % 16 : 0;
            extraLen += (2 + Utilities.random.nextInt(3)) * 16;

            NativeByteBuffer dataForEncryption = new NativeByteBuffer(len + extraLen);
            toEncrypt.position(0);
            dataForEncryption.writeBytes(toEncrypt);
            if (extraLen != 0) {
                byte[] b = new byte[extraLen];
                Utilities.random.nextBytes(b);
                dataForEncryption.writeBytes(b);
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

            Utilities.random.nextBytes(auth_key);

            long startTime = System.currentTimeMillis();

            for (int i = 0; i < n; i++) {
                performSendEncryptedRequest(req, 217, false, auth_key);
            }

            long endTime = System.currentTimeMillis();


            Log.d("MyTest", String.format("Normal time: %d", endTime - startTime));

        });
    }
}