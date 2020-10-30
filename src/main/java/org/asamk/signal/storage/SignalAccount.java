package org.asamk.signal.storage;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.asamk.signal.manager.GroupId;
import de.hehoe.purple_signal.PurpleSignal;
import org.asamk.signal.storage.contacts.ContactInfo;
import org.asamk.signal.storage.contacts.JsonContactsStore;
import org.asamk.signal.storage.groups.GroupInfo;
import org.asamk.signal.storage.groups.GroupInfoV1;
import org.asamk.signal.storage.groups.JsonGroupStore;
import org.asamk.signal.storage.profiles.ProfileStore;
import org.asamk.signal.storage.protocol.JsonIdentityKeyStore;
import org.asamk.signal.storage.protocol.JsonSignalProtocolStore;
import org.asamk.signal.storage.protocol.RecipientStore;
import org.asamk.signal.storage.protocol.SessionInfo;
import org.asamk.signal.storage.protocol.SignalServiceAddressResolver;
import org.asamk.signal.storage.stickers.StickerStore;
import org.asamk.signal.storage.threads.LegacyJsonThreadStore;
import org.asamk.signal.storage.threads.ThreadInfo;
import org.asamk.signal.util.Util;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.profiles.ProfileKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.Medium;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.util.Base64;

import java.io.Closeable;
import java.io.IOException;
import java.util.Collection;
import java.util.UUID;
import java.util.stream.Collectors;

public class SignalAccount implements Closeable {

    final static Logger logger = LoggerFactory.getLogger(SignalAccount.class);

    private final ObjectMapper jsonProcessor = new ObjectMapper();
    final static String PURPLE_SIGNALDATA_KEY = "signaldata";
    private final long connection;
    private String username;
    private UUID uuid;
    private int deviceId = SignalServiceAddress.DEFAULT_DEVICE_ID;
    private boolean isMultiDevice = false;
    private String password;
    private String registrationLockPin;
    private String signalingKey;
    private ProfileKey profileKey;
    private int preKeyIdOffset;
    private int nextSignedPreKeyId;

    private boolean registered = false;

    private JsonSignalProtocolStore signalProtocolStore;
    private JsonGroupStore groupStore;
    private JsonContactsStore contactStore;
    private RecipientStore recipientStore;
    private ProfileStore profileStore;
    private StickerStore stickerStore;

    private SignalAccount(final long connection) {
        this.connection = connection;
        jsonProcessor.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE); // disable autodetect
        jsonProcessor.disable(SerializationFeature.INDENT_OUTPUT); // for pretty print, you can disable it.
        jsonProcessor.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        jsonProcessor.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);
        jsonProcessor.disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
    }

    public static SignalAccount load(File dataPath, String username) throws IOException {
        final long connection = PurpleSignal.lookupUsername(username);
        SignalAccount account = new SignalAccount(connection);
        account.load();
        return account;
    }

    public static SignalAccount create(
            File dataPath, String username, IdentityKeyPair identityKey, int registrationId, ProfileKey profileKey
    ) throws IOException {
        final long connection = PurpleSignal.lookupUsername(username);
        SignalAccount account = new SignalAccount(connection);

        account.username = username;
        account.profileKey = profileKey;
        account.signalProtocolStore = new JsonSignalProtocolStore(identityKey, registrationId);
        account.groupStore = new JsonGroupStore(getGroupCachePath(dataPath, username));
        account.contactStore = new JsonContactsStore();
        account.recipientStore = new RecipientStore();
        account.profileStore = new ProfileStore();
        account.stickerStore = new StickerStore();
        account.registered = false;

        return account;
    }

    public static SignalAccount createLinkedAccount(
            File dataPath,
            String username,
            UUID uuid,
            String password,
            int deviceId,
            IdentityKeyPair identityKey,
            int registrationId,
            String signalingKey,
            ProfileKey profileKey
    ) throws IOException {
        final long connection = PurpleSignal.lookupUsername(username);
        SignalAccount account = new SignalAccount(connection);

        account.username = username;
        account.uuid = uuid;
        account.password = password;
        account.profileKey = profileKey;
        account.deviceId = deviceId;
        account.signalingKey = signalingKey;
        account.signalProtocolStore = new JsonSignalProtocolStore(identityKey, registrationId);
        account.groupStore = new JsonGroupStore(getGroupCachePath(dataPath, username));
        account.contactStore = new JsonContactsStore();
        account.recipientStore = new RecipientStore();
        account.profileStore = new ProfileStore();
        account.stickerStore = new StickerStore();
        account.registered = true;
        account.isMultiDevice = true;

        return account;
    }

    public static File getFileName(File dataPath, String username) {
        return new File(dataPath, username);
    }

    private static File getUserPath(final File dataPath, final String username) {
        return new File(dataPath, username + ".d");
    }

    public static File getMessageCachePath(File dataPath, String username) {
        return new File(getUserPath(dataPath, username), "msg-cache");
    }

    private static File getGroupCachePath(File dataPath, String username) {
        return new File(getUserPath(dataPath, username), "group-cache");
    }

    public static boolean userExists(final long connection) {
        return !PurpleSignal.getSettingsStringNatively(connection, PURPLE_SIGNALDATA_KEY, "").equals("");
    }

    public static boolean userExists(String dataPath, String username) {
        if (username == null) {
            return false;
        }
        try {
            return userExists(PurpleSignal.lookupUsername(username));
        } catch (IOException e) {
            return false;
        }
    }

    private void load(File dataPath) throws IOException {
        JsonNode rootNode;
        String json = PurpleSignal.getSettingsStringNatively(this.connection, PURPLE_SIGNALDATA_KEY, "");
        rootNode = jsonProcessor.readTree(json);

        JsonNode uuidNode = rootNode.get("uuid");
        if (uuidNode != null && !uuidNode.isNull()) {
            try {
                uuid = UUID.fromString(uuidNode.asText());
            } catch (IllegalArgumentException e) {
                throw new IOException("Config file contains an invalid uuid, needs to be a valid UUID", e);
            }
        }
        JsonNode node = rootNode.get("deviceId");
        if (node != null) {
            deviceId = node.asInt();
        }
        if (rootNode.has("isMultiDevice")) {
            isMultiDevice = Util.getNotNullNode(rootNode, "isMultiDevice").asBoolean();
        }
        username = Util.getNotNullNode(rootNode, "username").asText();
        password = Util.getNotNullNode(rootNode, "password").asText();
        JsonNode pinNode = rootNode.get("registrationLockPin");
        registrationLockPin = pinNode == null || pinNode.isNull() ? null : pinNode.asText();
        if (rootNode.has("signalingKey")) {
            signalingKey = Util.getNotNullNode(rootNode, "signalingKey").asText();
        }
        if (rootNode.has("preKeyIdOffset")) {
            preKeyIdOffset = Util.getNotNullNode(rootNode, "preKeyIdOffset").asInt(0);
        } else {
            preKeyIdOffset = 0;
        }
        if (rootNode.has("nextSignedPreKeyId")) {
            nextSignedPreKeyId = Util.getNotNullNode(rootNode, "nextSignedPreKeyId").asInt();
        } else {
            nextSignedPreKeyId = 0;
        }
        if (rootNode.has("profileKey")) {
            try {
                profileKey = new ProfileKey(Base64.decode(Util.getNotNullNode(rootNode, "profileKey").asText()));
            } catch (InvalidInputException e) {
                throw new IOException(
                        "Config file contains an invalid profileKey, needs to be base64 encoded array of 32 bytes",
                        e);
            }
        }

        signalProtocolStore = jsonProcessor.convertValue(Util.getNotNullNode(rootNode, "axolotlStore"),
                JsonSignalProtocolStore.class);
        registered = Util.getNotNullNode(rootNode, "registered").asBoolean();
        JsonNode groupStoreNode = rootNode.get("groupStore");
        if (groupStoreNode != null) {
            groupStore = jsonProcessor.convertValue(groupStoreNode, JsonGroupStore.class);
            groupStore.groupCachePath = getGroupCachePath(dataPath, username);
        }
        if (groupStore == null) {
            groupStore = new JsonGroupStore(getGroupCachePath(dataPath, username));
        }

        JsonNode contactStoreNode = rootNode.get("contactStore");
        if (contactStoreNode != null) {
            contactStore = jsonProcessor.convertValue(contactStoreNode, JsonContactsStore.class);
        }
        if (contactStore == null) {
            contactStore = new JsonContactsStore();
        }

        JsonNode recipientStoreNode = rootNode.get("recipientStore");
        if (recipientStoreNode != null) {
            recipientStore = jsonProcessor.convertValue(recipientStoreNode, RecipientStore.class);
        }
        if (recipientStore == null) {
            recipientStore = new RecipientStore();

            recipientStore.resolveServiceAddress(getSelfAddress());

            for (ContactInfo contact : contactStore.getContacts()) {
                recipientStore.resolveServiceAddress(contact.getAddress());
            }

            for (GroupInfo group : groupStore.getGroups()) {
                if (group instanceof GroupInfoV1) {
                    GroupInfoV1 groupInfoV1 = (GroupInfoV1) group;
                    groupInfoV1.members = groupInfoV1.members.stream()
                            .map(m -> recipientStore.resolveServiceAddress(m))
                            .collect(Collectors.toSet());
                }
            }

            for (SessionInfo session : signalProtocolStore.getSessions()) {
                session.address = recipientStore.resolveServiceAddress(session.address);
            }

            for (JsonIdentityKeyStore.Identity identity : signalProtocolStore.getIdentities()) {
                identity.setAddress(recipientStore.resolveServiceAddress(identity.getAddress()));
            }
        }

        JsonNode profileStoreNode = rootNode.get("profileStore");
        if (profileStoreNode != null) {
            profileStore = jsonProcessor.convertValue(profileStoreNode, ProfileStore.class);
        }
        if (profileStore == null) {
            profileStore = new ProfileStore();
        }

        JsonNode stickerStoreNode = rootNode.get("stickerStore");
        if (stickerStoreNode != null) {
            stickerStore = jsonProcessor.convertValue(stickerStoreNode, StickerStore.class);
        }
        if (stickerStore == null) {
            stickerStore = new StickerStore();
        }

        JsonNode threadStoreNode = rootNode.get("threadStore");
        if (threadStoreNode != null) {
            LegacyJsonThreadStore threadStore = jsonProcessor.convertValue(threadStoreNode,
                    LegacyJsonThreadStore.class);
            // Migrate thread info to group and contact store
            for (ThreadInfo thread : threadStore.getThreads()) {
                if (thread.id == null || thread.id.isEmpty()) {
                    continue;
                }
                try {
                    ContactInfo contactInfo = contactStore.getContact(new SignalServiceAddress(null, thread.id));
                    if (contactInfo != null) {
                        contactInfo.messageExpirationTime = thread.messageExpirationTime;
                        contactStore.updateContact(contactInfo);
                    } else {
                        GroupInfo groupInfo = groupStore.getGroup(GroupId.fromBase64(thread.id));
                        if (groupInfo instanceof GroupInfoV1) {
                            ((GroupInfoV1) groupInfo).messageExpirationTime = thread.messageExpirationTime;
                            groupStore.updateGroup(groupInfo);
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }
    }

    public void save() {
        ObjectNode rootNode = jsonProcessor.createObjectNode();
        rootNode.put("username", username)
                .put("uuid", uuid == null ? null : uuid.toString())
                .put("deviceId", deviceId)
                .put("isMultiDevice", isMultiDevice)
                .put("password", password)
                .put("registrationLockPin", registrationLockPin)
                .put("signalingKey", signalingKey)
                .put("preKeyIdOffset", preKeyIdOffset)
                .put("nextSignedPreKeyId", nextSignedPreKeyId)
                .put("profileKey", Base64.encodeBytes(profileKey.serialize()))
                .put("registered", registered)
                .putPOJO("axolotlStore", signalProtocolStore)
                .putPOJO("groupStore", groupStore)
                .putPOJO("contactStore", contactStore)
                .putPOJO("recipientStore", recipientStore)
                .putPOJO("profileStore", profileStore)
                .putPOJO("stickerStore", stickerStore);
        try {
            // Write to memory first to prevent corrupting the file in case of serialization errors
            String json = jsonProcessor.writeValueAsString(rootNode);
            PurpleSignal.setSettingsStringNatively(this.connection, PURPLE_SIGNALDATA_KEY, json);
        } catch (Exception e) {
            logger.error("Error saving file: {}", e.getMessage());
        }
    }

    private static Pair<FileChannel, FileLock> openFileChannel(File fileName) throws IOException {
        FileChannel fileChannel = new RandomAccessFile(fileName, "rw").getChannel();
        FileLock lock = fileChannel.tryLock();
        if (lock == null) {
            logger.info("Config file is in use by another instance, waiting…");
            lock = fileChannel.lock();
            logger.info("Config file lock acquired.");
        }
        return new Pair<>(fileChannel, lock);
    }

    public void setResolver(final SignalServiceAddressResolver resolver) {
        signalProtocolStore.setResolver(resolver);
    }

    public void addPreKeys(Collection<PreKeyRecord> records) {
        for (PreKeyRecord record : records) {
            signalProtocolStore.storePreKey(record.getId(), record);
        }
        preKeyIdOffset = (preKeyIdOffset + records.size()) % Medium.MAX_VALUE;
    }

    public void addSignedPreKey(SignedPreKeyRecord record) {
        signalProtocolStore.storeSignedPreKey(record.getId(), record);
        nextSignedPreKeyId = (nextSignedPreKeyId + 1) % Medium.MAX_VALUE;
    }

    public JsonSignalProtocolStore getSignalProtocolStore() {
        return signalProtocolStore;
    }

    public JsonGroupStore getGroupStore() {
        return groupStore;
    }

    public JsonContactsStore getContactStore() {
        return contactStore;
    }

    public RecipientStore getRecipientStore() {
        return recipientStore;
    }

    public ProfileStore getProfileStore() {
        return profileStore;
    }

    public StickerStore getStickerStore() {
        return stickerStore;
    }

    public String getUsername() {
        return username;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(final UUID uuid) {
        this.uuid = uuid;
    }

    public SignalServiceAddress getSelfAddress() {
        return new SignalServiceAddress(uuid, username);
    }

    public int getDeviceId() {
        return deviceId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    public String getRegistrationLockPin() {
        return registrationLockPin;
    }

    public String getRegistrationLock() {
        return null; // TODO implement KBS
    }

    public void setRegistrationLockPin(final String registrationLockPin) {
        this.registrationLockPin = registrationLockPin;
    }

    public String getSignalingKey() {
        return signalingKey;
    }

    public void setSignalingKey(final String signalingKey) {
        this.signalingKey = signalingKey;
    }

    public ProfileKey getProfileKey() {
        return profileKey;
    }

    public void setProfileKey(final ProfileKey profileKey) {
        this.profileKey = profileKey;
    }

    public int getPreKeyIdOffset() {
        return preKeyIdOffset;
    }

    public int getNextSignedPreKeyId() {
        return nextSignedPreKeyId;
    }

    public boolean isRegistered() {
        return registered;
    }

    public void setRegistered(final boolean registered) {
        this.registered = registered;
    }

    public boolean isMultiDevice() {
        return isMultiDevice;
    }

    public void setMultiDevice(final boolean multiDevice) {
        isMultiDevice = multiDevice;
    }

    @Override
    public void close() throws IOException {
        // nothing to do in this implementation
    }
}
