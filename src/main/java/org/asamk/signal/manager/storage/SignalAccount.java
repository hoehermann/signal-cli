package org.asamk.signal.manager.storage;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

import de.hehoe.purple_signal.PurpleSignal;
import org.asamk.signal.manager.groups.GroupId;
import org.asamk.signal.manager.storage.contacts.ContactInfo;
import org.asamk.signal.manager.storage.contacts.JsonContactsStore;
import org.asamk.signal.manager.storage.groups.GroupInfo;
import org.asamk.signal.manager.storage.groups.GroupInfoV1;
import org.asamk.signal.manager.storage.groups.JsonGroupStore;
import org.asamk.signal.manager.storage.messageCache.CachedMessage;
import org.asamk.signal.manager.storage.messageCache.MessageCache;
import org.asamk.signal.manager.storage.profiles.ProfileStore;
import org.asamk.signal.manager.storage.protocol.IdentityInfo;
import org.asamk.signal.manager.storage.protocol.JsonSignalProtocolStore;
import org.asamk.signal.manager.storage.protocol.RecipientStore;
import org.asamk.signal.manager.storage.protocol.SessionInfo;
import org.asamk.signal.manager.storage.protocol.SignalServiceAddressResolver;
import org.asamk.signal.manager.storage.stickers.StickerStore;
import org.asamk.signal.manager.storage.threads.LegacyJsonThreadStore;
import org.asamk.signal.manager.storage.threads.ThreadInfo;
import org.asamk.signal.manager.util.Utils;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.profiles.ProfileKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.Medium;
import org.whispersystems.signalservice.api.crypto.UnidentifiedAccess;
import org.whispersystems.signalservice.api.kbs.MasterKey;
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.storage.StorageKey;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class SignalAccount implements Closeable {

    final static Logger logger = LoggerFactory.getLogger(SignalAccount.class);

    private final ObjectMapper jsonProcessor = new ObjectMapper();
    final static String PURPLE_SIGNALDATA_KEY = "signaldata";
    private final long account;
    private String username;
    private UUID uuid;
    private int deviceId = SignalServiceAddress.DEFAULT_DEVICE_ID;
    private boolean isMultiDevice = false;
    private String password;
    private String registrationLockPin;
    private MasterKey pinMasterKey;
    private StorageKey storageKey;
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
    private SignalAccount(final long account) {
    	this.account = account;
        jsonProcessor.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE); // disable autodetect
        jsonProcessor.disable(SerializationFeature.INDENT_OUTPUT); // for pretty print, you can disable it.
        jsonProcessor.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        jsonProcessor.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);
        jsonProcessor.disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
    }

    public static SignalAccount load(File dataPath, String username) throws IOException {
        SignalAccount account = new SignalAccount(PurpleSignal.lookupAccountByUsername(username));
        account.load();
        return account;
    }

    public static SignalAccount create(
            File dataPath, String username, IdentityKeyPair identityKey, int registrationId, ProfileKey profileKey
    ) throws IOException {
        SignalAccount account = new SignalAccount(PurpleSignal.lookupAccountByUsername(username));

        account.username = username;
        account.profileKey = profileKey;
        account.signalProtocolStore = new JsonSignalProtocolStore(identityKey, registrationId);
        account.groupStore = new JsonGroupStore(PurpleSignal.lookupAccountByUsername(username));
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
        SignalAccount account = new SignalAccount(PurpleSignal.lookupAccountByUsername(username));

        account.username = username;
        account.uuid = uuid;
        account.password = password;
        account.profileKey = profileKey;
        account.deviceId = deviceId;
        account.signalingKey = signalingKey;
        account.signalProtocolStore = new JsonSignalProtocolStore(identityKey, registrationId);
        account.groupStore = new JsonGroupStore(PurpleSignal.lookupAccountByUsername(username));
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

    public static boolean userExists(final long account) {
        return !PurpleSignal.getSettingsStringNatively(account, PURPLE_SIGNALDATA_KEY, "").equals("");
    }

    public static boolean userExists(File dataPath, String username) {
        if (username == null) {
            return false;
        }
        try {
            return userExists(PurpleSignal.lookupAccountByUsername(username));
        } catch (IOException e) {
            return false;
        }
    }

    private void load() throws IOException {
        JsonNode rootNode;
        String json = PurpleSignal.getSettingsStringNatively(this.account, PURPLE_SIGNALDATA_KEY, "");
        rootNode = jsonProcessor.readTree(json);

        if (rootNode.hasNonNull("uuid")) {
            try {
                uuid = UUID.fromString(rootNode.get("uuid").asText());
            } catch (IllegalArgumentException e) {
                throw new IOException("Config file contains an invalid uuid, needs to be a valid UUID", e);
            }
        }
        if (rootNode.hasNonNull("deviceId")) {
            deviceId = rootNode.get("deviceId").asInt();
        }
        if (rootNode.hasNonNull("isMultiDevice")) {
            isMultiDevice = rootNode.get("isMultiDevice").asBoolean();
        }
        username = Utils.getNotNullNode(rootNode, "username").asText();
        password = Utils.getNotNullNode(rootNode, "password").asText();
        if (rootNode.hasNonNull("registrationLockPin")) {
            registrationLockPin = rootNode.get("registrationLockPin").asText();
        }
        if (rootNode.hasNonNull("pinMasterKey")) {
            pinMasterKey = new MasterKey(Base64.getDecoder().decode(rootNode.get("pinMasterKey").asText()));
        }
        if (rootNode.hasNonNull("storageKey")) {
            storageKey = new StorageKey(Base64.getDecoder().decode(rootNode.get("storageKey").asText()));
        }
        if (rootNode.hasNonNull("signalingKey")) {
            signalingKey = rootNode.get("signalingKey").asText();
            if (signalingKey.equals("null")) {
                // Workaround for load bug in older versions
                signalingKey = null;
            }
        }
        if (rootNode.hasNonNull("preKeyIdOffset")) {
            preKeyIdOffset = rootNode.get("preKeyIdOffset").asInt(0);
        } else {
            preKeyIdOffset = 0;
        }
        if (rootNode.hasNonNull("nextSignedPreKeyId")) {
            nextSignedPreKeyId = rootNode.get("nextSignedPreKeyId").asInt();
        } else {
            nextSignedPreKeyId = 0;
        }
        if (rootNode.hasNonNull("profileKey")) {
            try {
                profileKey = new ProfileKey(Base64.getDecoder().decode(rootNode.get("profileKey").asText()));
            } catch (InvalidInputException e) {
                throw new IOException(
                        "Config file contains an invalid profileKey, needs to be base64 encoded array of 32 bytes",
                        e);
            }
        }

        signalProtocolStore = jsonProcessor.convertValue(Utils.getNotNullNode(rootNode, "axolotlStore"),
                JsonSignalProtocolStore.class);
        registered = Utils.getNotNullNode(rootNode, "registered").asBoolean();
        groupStore = new JsonGroupStore(this.account);

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

            for (IdentityInfo identity : signalProtocolStore.getIdentities()) {
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
                .put("pinMasterKey",
                        pinMasterKey == null ? null : Base64.getEncoder().encodeToString(pinMasterKey.serialize()))
                .put("storageKey",
                        storageKey == null ? null : Base64.getEncoder().encodeToString(storageKey.serialize()))
                .put("signalingKey", signalingKey)
                .put("preKeyIdOffset", preKeyIdOffset)
                .put("nextSignedPreKeyId", nextSignedPreKeyId)
                .put("profileKey", Base64.getEncoder().encodeToString(profileKey.serialize()))
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
            PurpleSignal.setSettingsStringNatively(this.account, PURPLE_SIGNALDATA_KEY, json);
        } catch (JsonProcessingException e) {
        	PurpleSignal.logNatively(PurpleSignal.DEBUG_LEVEL_ERROR, e.getMessage());
        }
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
    
    public MessageCache getMessageCache() {
        return new MessageCache(null) {
        	@Override
			public List<CachedMessage> getCachedMessages() {
        		return java.util.Collections.emptyList();
        	}
        	@Override
        	public CachedMessage cacheMessage(SignalServiceEnvelope envelope) {
				return null;
        	}
        };
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

    public void setDeviceId(final int deviceId) {
        this.deviceId = deviceId;
    }

    public boolean isMasterDevice() {
        return deviceId == SignalServiceAddress.DEFAULT_DEVICE_ID;
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

    public void setRegistrationLockPin(final String registrationLockPin) {
        this.registrationLockPin = registrationLockPin;
    }

    public MasterKey getPinMasterKey() {
        return pinMasterKey;
    }

    public void setPinMasterKey(final MasterKey pinMasterKey) {
        this.pinMasterKey = pinMasterKey;
    }

    public StorageKey getStorageKey() {
        if (pinMasterKey != null) {
            return pinMasterKey.deriveStorageServiceKey();
        }
        return storageKey;
    }

    public void setStorageKey(final StorageKey storageKey) {
        this.storageKey = storageKey;
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

    public byte[] getSelfUnidentifiedAccessKey() {
        return UnidentifiedAccess.deriveAccessKeyFrom(getProfileKey());
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

    public boolean isUnrestrictedUnidentifiedAccess() {
        // TODO make configurable
        return false;
    }

    public boolean isDiscoverableByPhoneNumber() {
        // TODO make configurable
        return true;
    }

    @Override
    public void close() throws IOException {
        // nothing to do in this implementation
    }
}
