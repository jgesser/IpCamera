/**
 * Copyright (c) 2010-2020 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.openhab.binding.ipcamera.onvif;

import static org.openhab.binding.ipcamera.IpCameraBindingConstants.*;

import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedList;
import java.util.Random;
import java.util.TimeZone;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.ipcamera.handler.IpCameraHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.timeout.IdleStateHandler;

/**
 * The {@link OnvifConnection} is a WIP and is currently not used. Will eventually remove the need for an external ONVIF
 * lib.
 *
 *
 * @author Matthew Skinner - Initial contribution
 */

@NonNullByDefault
public class OnvifConnection extends ChannelDuplexHandler {
    @Nullable
    Bootstrap bootstrap;
    EventLoopGroup mainEventLoopGroup = new NioEventLoopGroup();
    String ipAddress = "";
    String user = "";
    String password = "";
    int onvifPort = 80;
    String deviceXAddr = "/onvif/device_service";
    String eventXAddr = "/onvif/device_service";
    String mediaXAddr = "/onvif/device_service";
    String imagingXAddr = "/onvif/device_service";
    String ptzXAddr = "/onvif/ptz_service";
    String subscriptionXAddr = "/onvif/device_service";
    boolean isConnected = false;
    int mediaProfileIndex = 0;
    String snapshotUri = "";
    String rtspUri = "";
    IpCameraHandler ipCameraHandler;
    boolean useEvents = false;
    boolean pullMessagesWorking = false;

    // These hold the cameras PTZ position in the range that the camera uses, ie
    // mine is -1 to +1
    private Float panRangeMin = -1.0f;
    private Float panRangeMax = 1.0f;
    private Float tiltRangeMin = -1.0f;
    private Float tiltRangeMax = 1.0f;
    private Float zoomMin = 0.0f;
    private Float zoomMax = 1.0f;
    // These hold the PTZ values for updating Openhabs controls in 0-100 range
    private Float currentPanPercentage = 0.0f;
    private Float currentTiltPercentage = 0.0f;
    private Float currentZoomPercentage = 0.0f;
    private Float currentPanCamValue = 0.0f;
    public Float currentTiltCamValue = 0.0f;
    public Float currentZoomCamValue = 0.0f;
    public String ptzNodeToken = "000";
    public String ptzConfigToken = "000";
    int presetTokenIndex = 0;
    LinkedList<String> presetTokens = new LinkedList<String>();
    LinkedList<String> mediaProfileTokens = new LinkedList<String>();
    boolean ptzDevice = true;
    private final Logger logger = LoggerFactory.getLogger(getClass());

    public OnvifConnection(IpCameraHandler ipCameraHandler, String ipAddress, String user, String password) {
        this.ipCameraHandler = ipCameraHandler;
        if (!ipAddress.equals("")) {
            this.user = user;
            this.password = password;
            getIPandPortFromUrl(ipAddress);
        }
    }

    // TODO: Some cameras may need to poll the messages, this gives the beginning of that support.
    public boolean isEventRunning() {
        if (pullMessagesWorking) {
            pullMessagesWorking = false;
            return true;
        } else {
            sendEventRequest("PullMessages");
        }
        return false;
    }

    String getXml(String requestType) {
        switch (requestType) {
            case "AbsoluteMove":
                return "<AbsoluteMove xmlns=\"http://www.onvif.org/ver20/ptz/wsdl\"><ProfileToken>"
                        + mediaProfileTokens.get(mediaProfileIndex) + "</ProfileToken><Position><PanTilt x=\""
                        + currentPanCamValue + "\" y=\"" + currentTiltCamValue
                        + "\" space=\"http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace\">\n"
                        + "</PanTilt>\n" + "<Zoom x=\"" + currentZoomCamValue
                        + "\" space=\"http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace\">\n"
                        + "</Zoom>\n" + "</Position>\n"
                        + "<Speed><PanTilt x=\"0.1\" y=\"0.1\" space=\"http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace\"></PanTilt><Zoom x=\"1.0\" space=\"http://www.onvif.org/ver10/tptz/ZoomSpaces/ZoomGenericSpeedSpace\"></Zoom>\n"
                        + "</Speed></AbsoluteMove>";
            case "AddPTZConfiguration": // not tested to work yet
                return "<AddPTZConfiguration xmlns=\"http://www.onvif.org/ver20/ptz/wsdl\"><ProfileToken>"
                        + mediaProfileTokens.get(mediaProfileIndex) + "</ProfileToken><ConfigurationToken>"
                        + ptzConfigToken + "</ConfigurationToken></AddPTZConfiguration>";
            case "CreatePullPointSubscription":
                return "<CreatePullPointSubscription xmlns=\"http://www.onvif.org/ver10/events/wsdl\"><InitialTerminationTime>PT10M</InitialTerminationTime></CreatePullPointSubscription>";
            case "GetCapabilities":
                return "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>All</Category></GetCapabilities>";

            case "GetDeviceInformation":// needs auth for some cameras.
                return "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
            case "GetProfiles":
                return "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>";
            case "GetSnapshotUri":
                return "<GetSnapshotUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><ProfileToken>"
                        + mediaProfileTokens.get(mediaProfileIndex) + "</ProfileToken></GetSnapshotUri>";
            case "GetStreamUri":
                return "<GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><StreamSetup><Stream xmlns=\"http://www.onvif.org/ver10/schema\">RTP-Unicast</Stream><Transport xmlns=\"http://www.onvif.org/ver10/schema\"><Protocol>RTSP</Protocol></Transport></StreamSetup><ProfileToken>"
                        + mediaProfileTokens.get(mediaProfileIndex) + "</ProfileToken></GetStreamUri>";
            case "GetSystemDateAndTime":
                return "<GetSystemDateAndTime xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
            case "Subscribe":
                return "<Subscribe xmlns=\"http://docs.oasis-open.org/wsn/b-2/\"><ConsumerReference><Address>http://"
                        + ipCameraHandler.hostIp + ":" + ipCameraHandler.serverPort
                        + "/OnvifEvent</Address></ConsumerReference></Subscribe>";
            case "Unsubscribe":// not tested
                return "<Unsubscribe xmlns=\"http://docs.oasis-open.org/wsn/b-2/\"></Unsubscribe>";
            case "PullMessages":
                return "<PullMessages xmlns=\"http://www.onvif.org/ver10/events/wsdl\"><Timeout>PT30S</Timeout><MessageLimit>1</MessageLimit></PullMessages>";
            case "GetEventProperties":
                return "<GetEventProperties xmlns=\"http://www.onvif.org/ver10/events/wsdl\"/>";
            case "Renew":
                return "<Renew xmlns=\"http://docs.oasis-open.org/wsn/b-2\"><TerminationTime>PT10M</TerminationTime></Renew>";
            case "GetConfigurations":
                return "<GetConfigurations xmlns=\"http://www.onvif.org/ver20/ptz/wsdl\"></GetConfigurations>";
            case "GetConfigurationOptions":
                return "<GetConfigurationOptions xmlns=\"http://www.onvif.org/ver20/ptz/wsdl\"><ConfigurationToken>"
                        + ptzConfigToken + "</ConfigurationToken></GetConfigurationOptions>";
            case "GetConfiguration":
                return "<GetConfiguration xmlns=\"http://www.onvif.org/ver20/ptz/wsdl\"><PTZConfigurationToken>"
                        + ptzConfigToken + "</PTZConfigurationToken></GetConfiguration>";
            case "SetConfiguration":// not tested to work yet
                return "<SetConfiguration xmlns=\"http://www.onvif.org/ver20/ptz/wsdl\"><PTZConfiguration><NodeToken>"
                        + ptzNodeToken
                        + "</NodeToken><DefaultAbsolutePantTiltPositionSpace>AbsolutePanTiltPositionSpace</DefaultAbsolutePantTiltPositionSpace><DefaultAbsoluteZoomPositionSpace>AbsoluteZoomPositionSpace</DefaultAbsoluteZoomPositionSpace></PTZConfiguration></SetConfiguration>";
            case "GetNodes":
                return "<GetNodes xmlns=\"http://www.onvif.org/ver20/ptz/wsdl\"></GetNodes>";
            case "GetStatus":
                return "<GetStatus xmlns=\"http://www.onvif.org/ver20/ptz/wsdl\"><ProfileToken>"
                        + mediaProfileTokens.get(mediaProfileIndex) + "</ProfileToken></GetStatus>";
            case "GotoPreset":
                return "<GotoPreset xmlns=\"http://www.onvif.org/ver20/ptz/wsdl\"><ProfileToken>"
                        + mediaProfileTokens.get(mediaProfileIndex) + "</ProfileToken><PresetToken>"
                        + presetTokens.get(presetTokenIndex)
                        + "</PresetToken><Speed><PanTilt x=\"0.0\" y=\"0.0\" space=\"\"></PanTilt><Zoom x=\"0.0\" space=\"\"></Zoom></Speed></GotoPreset>";
            case "GetPresets":
                return "<GetPresets xmlns=\"http://www.onvif.org/ver20/ptz/wsdl\"><ProfileToken>"
                        + mediaProfileTokens.get(mediaProfileIndex) + "</ProfileToken></GetPresets>";
        }
        return "notfound";
    }

    public void processReply(String message) {
        logger.trace("Onvif reply is:{}", message);
        if (message.contains("PullMessagesResponse")) {
            eventRecieved(message);
            pullMessagesWorking = true;
            sendOnvifRequest(requestBuilder("PullMessages", subscriptionXAddr));
            // sendOnvifRequest(requestBuilder("Renew", eventXAddr));
        } else if (message.contains("GetSystemDateAndTimeResponse")) {// 1st to be sent.
            sendOnvifRequest(requestBuilder("GetCapabilities", deviceXAddr));
            parseDateAndTime(message);
            logger.debug("Openhabs UTC dateTime is:{}", getUTCdateTime());
        } else if (message.contains("GetEventPropertiesResponse")) {
            sendOnvifRequest(requestBuilder("CreatePullPointSubscription", eventXAddr));
            sendOnvifRequest(requestBuilder("Subscribe", eventXAddr));
        } else if (message.contains("SubscribeResponse")) {
            logger.info("Onvif Subscribe appears to be working for Alarms/Events.");
        } else if (message.contains("CreatePullPointSubscriptionResponse")) {
            subscriptionXAddr = removeIPfromUrl(fetchXML(message, "SubscriptionReference>", "Address>"));
            logger.debug("subscriptionXAddr={}", subscriptionXAddr);
            sendOnvifRequest(requestBuilder("PullMessages", subscriptionXAddr));
        } else if (message.contains("GetProfilesResponse")) {// 3rd to be sent.
            parseProfiles(message);
            isConnected = true;
            sendOnvifRequest(requestBuilder("GetSnapshotUri", mediaXAddr));
            sendOnvifRequest(requestBuilder("GetStreamUri", mediaXAddr));
            if (ptzDevice) {
                sendPTZRequest("GetNodes");
            }
            if (useEvents) {// stops API cameras from getting sent ONVIF events.
                sendOnvifRequest(requestBuilder("GetEventProperties", eventXAddr));
            }
        } else if (message.contains("GetStatusResponse")) {
            processPTZLocation(message);
        } else if (message.contains("GetPresetsResponse")) {
            presetTokens = listOfResults(message, "<tptz:Preset", "token=\"");
        } else if (message.contains("GetConfigurationsResponse")) {
            sendPTZRequest("GetPresets");
            ptzConfigToken = fetchXML(message, "PTZConfiguration", "token=\"");
            logger.debug("ptzConfigToken={}", ptzConfigToken);
            sendPTZRequest("GetConfigurationOptions");
        } else if (message.contains("GetNodesResponse")) {
            sendPTZRequest("GetStatus");
            ptzNodeToken = fetchXML(message, "", "token=\"");
            logger.debug("ptzNodeToken={}", ptzNodeToken);
            sendPTZRequest("GetConfigurations");
        } else if (message.contains("GetCapabilitiesResponse")) {// 2nd to be sent.
            parseXAddr(message);
            sendOnvifRequest(requestBuilder("GetProfiles", mediaXAddr));
        } else if (message.contains("GetDeviceInformationResponse")) {
            logger.debug("GetDeviceInformationResponse recieved");
        } else if (message.contains("GetSnapshotUriResponse")) {
            snapshotUri = removeIPfromUrl(fetchXML(message, "MediaUri>", ":Uri>"));
            logger.debug("GetSnapshotUri:{}", snapshotUri);
            if (ipCameraHandler.snapshotUri.equals("")) {
                ipCameraHandler.snapshotUri = snapshotUri;
            }
        } else if (message.contains("GetStreamUriResponse")) {
            rtspUri = fetchXML(message, "MediaUri>", ":Uri>");
            logger.debug("GetStreamUri:{}", rtspUri);
            if (ipCameraHandler.rtspUri.equals("")) {
                ipCameraHandler.rtspUri = rtspUri;
            }
        } else {
            // logger.debug("Unhandled Onvif reply is:{}", message);
        }
    }

    HttpRequest requestBuilder(String requestType, String xAddr) {
        logger.debug("Sending ONVIF request:{}", requestType);
        String security = "";
        String extraEnvelope = " xmlns:a=\"http://www.w3.org/2005/08/addressing\"";
        String headerTo = "";
        if (requestType.equals("CreatePullPointSubscription") || requestType.equals("PullMessages")) {
            headerTo = "<a:To s:mustUnderstand=\"1\">http://" + ipAddress + xAddr + "</a:To>";
        }

        if (!password.equals("")) {
            String nonce = createNonce();
            String dateTime = getUTCdateTime();
            String digest = createDigest(nonce, dateTime);
            security = "<Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>"
                    + user
                    + "</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">"
                    + digest
                    + "</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">"
                    + encodeBase64(nonce)
                    + "</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                    + dateTime + "</Created></UsernameToken></Security>";
        }

        String headers = "<s:Header>" + security + headerTo + "</s:Header>";

        FullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, new HttpMethod("POST"), xAddr);
        request.headers().add(HttpHeaderNames.CONTENT_TYPE, "application/soap+xml; charset=utf-8");
        request.headers().set(HttpHeaderNames.HOST, ipAddress + ":" + onvifPort);
        request.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
        request.headers().set(HttpHeaderNames.ACCEPT_ENCODING, "gzip, deflate");
        String fullXml = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"" + extraEnvelope + ">"
                + headers
                + "<s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
                + getXml(requestType) + "</s:Body></s:Envelope>";
        ByteBuf bbuf = Unpooled.copiedBuffer(fullXml, StandardCharsets.UTF_8);
        request.headers().set(HttpHeaderNames.CONTENT_LENGTH, bbuf.readableBytes());
        request.content().clear().writeBytes(bbuf);
        return request;
    }

    String removeIPfromUrl(String url) {
        int index = url.indexOf(ipAddress);
        if (index != -1) {// now remove the :port
            index = url.indexOf("/", index + ipAddress.length());
        }
        if (index == -1) {
            logger.debug("We hit an issue parsing url:{}", url);
            return "";
        }
        return url.substring(index);
    }

    void parseXAddr(String message) {
        deviceXAddr = removeIPfromUrl(fetchXML(message, "<tt:Device>", "<tt:XAddr>"));
        logger.debug("deviceXAddr:{}", deviceXAddr);
        eventXAddr = removeIPfromUrl(fetchXML(message, "<tt:Events>", "<tt:XAddr>"));
        logger.debug("eventsXAddr:{}", eventXAddr);
        mediaXAddr = removeIPfromUrl(fetchXML(message, "<tt:Media>", "<tt:XAddr>"));
        logger.debug("mediaXAddr:{}", mediaXAddr);
        ptzXAddr = removeIPfromUrl(fetchXML(message, "<tt:PTZ>", "<tt:XAddr>"));
        if (ptzXAddr == "") {
            ptzDevice = false;
            logger.trace("Camera must not support PTZ, it failed to give a <tt:PTZ><tt:XAddr>:{}", message);
        } else {
            logger.debug("ptzXAddr:{}", ptzXAddr);
        }
    }

    private void parseDateAndTime(String message) {
        String minute = fetchXML(message, "UTCDateTime", "Minute>");
        String hour = fetchXML(message, "UTCDateTime", "Hour>");
        String second = fetchXML(message, "UTCDateTime", "Second>");
        logger.debug("Cameras  UTC time is : {}:{}:{}", hour, minute, second);
        String day = fetchXML(message, "UTCDateTime", "Day>");
        String month = fetchXML(message, "UTCDateTime", "Month>");
        String year = fetchXML(message, "UTCDateTime", "Year>");
        logger.debug("Cameras  UTC date is : {}-{}-{}", year, month, day);
    }

    private String getUTCdateTime() {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date());
    }

    public String createNonce() {
        Random nonce = new Random();
        return "" + nonce.nextInt();
    }

    String encodeBase64(String raw) {
        return Base64.getEncoder().encodeToString(raw.getBytes());
    }

    String createDigest(String nOnce, String dateTime) {
        String beforeEncryption = nOnce + dateTime + password;
        MessageDigest msgDigest;
        byte[] encryptedRaw = null;
        try {
            msgDigest = MessageDigest.getInstance("SHA-1");
            msgDigest.reset();
            msgDigest.update(beforeEncryption.getBytes("utf8"));
            encryptedRaw = msgDigest.digest();
        } catch (NoSuchAlgorithmException e) {
        } catch (UnsupportedEncodingException e) {
        }
        return Base64.getEncoder().encodeToString(encryptedRaw);
    }

    @SuppressWarnings("null")
    public void sendOnvifRequest(HttpRequest request) {
        if (bootstrap == null) {
            bootstrap = new Bootstrap();
            bootstrap.group(mainEventLoopGroup);
            bootstrap.channel(NioSocketChannel.class);
            bootstrap.option(ChannelOption.SO_KEEPALIVE, true);
            bootstrap.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000);
            bootstrap.option(ChannelOption.SO_SNDBUF, 1024 * 8);
            bootstrap.option(ChannelOption.SO_RCVBUF, 1024 * 1024);
            bootstrap.option(ChannelOption.TCP_NODELAY, true);
            bootstrap.handler(new ChannelInitializer<SocketChannel>() {

                @Override
                public void initChannel(SocketChannel socketChannel) throws Exception {
                    socketChannel.pipeline().addLast("idleStateHandler", new IdleStateHandler(62, 62, 62));
                    socketChannel.pipeline().addLast("HttpClientCodec", new HttpClientCodec());
                    socketChannel.pipeline().addLast("OnvifCodec", new OnvifCodec(getHandle()));
                }
            });
        }
        ChannelFuture chFuture = bootstrap.connect(new InetSocketAddress(ipAddress, onvifPort));
        chFuture.awaitUninterruptibly(); // ChannelOption.CONNECT_TIMEOUT_MILLIS means this will not hang here
        if (!chFuture.isSuccess()) {
            logger.debug("Camera is not reachable on ONVIF port:{} or the port may be wrong.", onvifPort);
        }
        Channel ch = chFuture.channel();
        ch.writeAndFlush(request);
        chFuture = null;
    }

    OnvifConnection getHandle() {
        return this;
    }

    void getIPandPortFromUrl(String url) {
        int beginIndex = url.indexOf(":");
        int endIndex = url.indexOf("/", beginIndex);
        if (beginIndex >= 0 && endIndex == -1) {// 192.168.1.1:8080
            ipAddress = url.substring(0, beginIndex);
            onvifPort = Integer.parseInt(url.substring(beginIndex + 1));
        } else if (beginIndex >= 0 && endIndex > beginIndex) {// 192.168.1.1:8080/foo/bar
            ipAddress = url.substring(0, beginIndex);
            onvifPort = Integer.parseInt(url.substring(beginIndex + 1, endIndex));
        } else {// 192.168.1.1
            ipAddress = url;
            logger.warn("No Onvif Port found when parsing:{}", url);
        }
    }

    public void gotoPreset(int index) {
        if (ptzDevice) {
            if (index > 0) {// 0 is reserved for HOME as cameras seem to start at preset 1.
                if (presetTokens.isEmpty()) {
                    logger.warn("Camera did not report any ONVIF preset locations to the binding");
                } else {
                    presetTokenIndex = index - 1;
                    sendPTZRequest("GotoPreset");
                }
            }
        }
    }

    public void eventRecieved(String eventMessage) {
        logger.debug("Onvif eventRecieved : {}", eventMessage);
        if (eventMessage.contains("Name=\"IsMotion\" Value=\"true\"")) {
            ipCameraHandler.motionDetected(CHANNEL_MOTION_ALARM);
        } else if (eventMessage.contains("Name=\"IsMotion\" Value=\"false\"")) {
            ipCameraHandler.noMotionDetected(CHANNEL_MOTION_ALARM);
        }
        if (eventMessage.contains("VideoSource/MotionAlarm")) { // PIR alarm from a HIK
            if (eventMessage.contains("SimpleItem Name=\"State\" Value=\"true\"")) {
                ipCameraHandler.motionDetected(CHANNEL_PIR_ALARM);
            } else if (eventMessage.contains("SimpleItem Name=\"State\" Value=\"false\"")) {
                ipCameraHandler.noMotionDetected(CHANNEL_PIR_ALARM);
            }
        }
    }

    public void connect(boolean useEvents) {
        sendOnvifRequest(requestBuilder("GetSystemDateAndTime", deviceXAddr));
        this.useEvents = useEvents;
        // sendOnvifRequest(requestBuilder("GetDeviceInformation", deviceXAddr));
    }

    public boolean isConnected() {
        return isConnected;
    }

    public void disconnect() {
        isConnected = false;
        presetTokens.clear();
        mediaProfileTokens.clear();
    }

    public boolean supportsPTZ() {
        return ptzDevice;
    }

    public void getStatus() {
        if (ptzDevice) {
            sendPTZRequest("GetStatus");
        }
    }

    public Float getAbsolutePan() {
        return currentPanPercentage;
    }

    public Float getAbsoluteTilt() {
        return currentTiltPercentage;
    }

    public Float getAbsoluteZoom() {
        return currentZoomPercentage;
    }

    public void setAbsolutePan(Float panValue) {// Value is 0-100% of cameras range
        if (ptzDevice) {
            currentPanPercentage = panValue;
            currentPanCamValue = ((((panRangeMin - panRangeMax) * -1) / 100) * panValue + panRangeMin);
        }
    }

    public void setAbsoluteTilt(Float tiltValue) {// Value is 0-100% of cameras range
        if (ptzDevice) {
            currentTiltPercentage = tiltValue;
            currentTiltCamValue = ((((panRangeMin - panRangeMax) * -1) / 100) * tiltValue + tiltRangeMin);
        }
    }

    public void setAbsoluteZoom(Float zoomValue) {// Value is 0-100% of cameras range
        if (ptzDevice) {
            currentZoomPercentage = zoomValue;
            currentZoomCamValue = ((((zoomMin - zoomMax) * -1) / 100) * zoomValue + zoomMin);
        }
    }

    public void absoluteMove() { // Camera wont move until PTZ values are set, then call this.
        if (ptzDevice) {
            sendPTZRequest("AbsoluteMove");
        }
    }

    public void setSelectedMediaProfile(int mediaProfileIndex) {
        this.mediaProfileIndex = mediaProfileIndex;
    }

    LinkedList<String> listOfResults(String message, String heading, String key) {
        LinkedList<String> results = new LinkedList<String>();
        String temp = "";
        for (int startLookingFromIndex = 0; startLookingFromIndex != -1;) {
            startLookingFromIndex = message.indexOf(heading, startLookingFromIndex);
            if (startLookingFromIndex >= 0) {
                temp = fetchXML(message.substring(startLookingFromIndex), heading, key);
                if (!temp.equals("")) {
                    logger.trace("String was found:{}", temp);
                    results.add(temp);
                    ++startLookingFromIndex;
                }
            } else {
                logger.trace("no more to find");
            }
        }
        return results;
    }

    String fetchXML(String message, String sectionHeading, String key) {
        String result = "";
        int sectionHeaderBeginning = 0;
        if (!sectionHeading.equals("")) {// looking for a sectionHeading
            sectionHeaderBeginning = message.indexOf(sectionHeading);
        }
        if (sectionHeaderBeginning == -1) {
            logger.debug("{} was not found in :{}", sectionHeading, message);
            return "";
        }
        int startIndex = message.indexOf(key, sectionHeaderBeginning + sectionHeading.length());
        if (startIndex == -1) {
            logger.debug("{} was not found in :{}", key, message);
            return "";
        }
        int endIndex = message.indexOf("<", startIndex + key.length());
        if (endIndex > startIndex) {
            result = message.substring(startIndex + key.length(), endIndex);
        }
        // remove any quotes and anything after the quote.
        sectionHeaderBeginning = result.indexOf("\"");
        if (sectionHeaderBeginning > 0) {
            result = result.substring(0, sectionHeaderBeginning);
        }
        return result;
    }

    void parseProfiles(String message) {
        mediaProfileTokens = listOfResults(message, "<trt:Profiles", "token=\"");
        if (mediaProfileIndex >= mediaProfileTokens.size()) {
            logger.error("You have set the media profile to {} when the camera reported {} profiles.",
                    mediaProfileIndex, mediaProfileTokens.size());
            mediaProfileIndex = 0;
        }
    }

    void processPTZLocation(String result) {
        logger.debug("Processing new PTZ location now");

        int beginIndex = result.indexOf("x=\"");
        int endIndex = result.indexOf("\"", (beginIndex + 3));
        if (beginIndex >= 0 && endIndex >= 0) {
            currentPanCamValue = Float.parseFloat(result.substring(beginIndex + 3, endIndex));
            currentPanPercentage = (((panRangeMin - currentPanCamValue) * -1) / ((panRangeMin - panRangeMax) * -1))
                    * 100;
            logger.debug("Pan is updating to:{} and the cam value is {}", Math.round(currentPanPercentage),
                    currentPanCamValue);
        } else {
            logger.warn("turning off PTZ functions as binding could not determin current PTZ locations.");
            ptzDevice = false;
            return;
        }

        beginIndex = result.indexOf("y=\"");
        endIndex = result.indexOf("\"", (beginIndex + 3));
        if (beginIndex >= 0 && endIndex >= 0) {
            currentTiltCamValue = Float.parseFloat(result.substring(beginIndex + 3, endIndex));
            currentTiltPercentage = (((tiltRangeMin - currentTiltCamValue) * -1) / ((tiltRangeMin - tiltRangeMax) * -1))
                    * 100;
            logger.debug("Tilt is updating to:{} and the cam value is {}", Math.round(currentTiltPercentage),
                    currentTiltCamValue);
        } else {
            logger.warn("turning off PTZ functions as binding could not determin current PTZ locations.");
            ptzDevice = false;
            return;
        }

        beginIndex = result.lastIndexOf("x=\"");
        endIndex = result.indexOf("\"", (beginIndex + 3));
        if (beginIndex >= 0 && endIndex >= 0) {
            currentZoomCamValue = Float.parseFloat(result.substring(beginIndex + 3, endIndex));
            currentZoomPercentage = (((zoomMin - currentZoomCamValue) * -1) / ((zoomMin - zoomMax) * -1)) * 100;
            logger.debug("Zoom is updating to:{} and the cam value is {}", Math.round(currentZoomPercentage),
                    currentZoomCamValue);
        } else {
            logger.warn("turning off PTZ functions as binding could not determin current PTZ locations.");
            ptzDevice = false;
            return;
        }
        ptzDevice = true;
    }

    public void sendPTZRequest(String string) {
        sendOnvifRequest(requestBuilder(string, ptzXAddr));
    }

    public void sendEventRequest(String string) {
        sendOnvifRequest(requestBuilder(string, eventXAddr));
    }
}
