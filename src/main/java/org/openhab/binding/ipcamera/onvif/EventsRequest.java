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

import static org.openhab.binding.ipcamera.IpCameraBindingConstants.CHANNEL_MOTION_ALARM;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.ipcamera.handler.IpCameraHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.teletask.onvif.OnvifManager;
import be.teletask.onvif.listeners.OnvifResponseListener;
import be.teletask.onvif.models.OnvifDevice;
import be.teletask.onvif.models.OnvifType;
import be.teletask.onvif.requests.OnvifRequest;
import be.teletask.onvif.responses.OnvifResponse;

/**
 * The {@link EventsRequest} is responsible for handling Onvif events and alarms which are not fully implemented or
 * tested yet.
 *
 * @author Matthew Skinner - Initial contribution
 */

@NonNullByDefault
public class EventsRequest implements OnvifRequest {
    public final Logger logger = LoggerFactory.getLogger(getClass());
    String profileToken = "";
    String requestType = "";
    String eventAddress = "";// todo implement this again.
    OnvifManager eventManager = new OnvifManager();
    OnvifDevice thisOnvifCamera = new OnvifDevice("none");
    String onvifServicesUrl = "";
    private IpCameraHandler ipCameraHandler;

    public EventsRequest(OnvifManager eventManager, OnvifDevice thisOnvifCamera, String onvifServicesUrl,
            IpCameraHandler ipCameraHandler) {
        this.eventManager = eventManager;
        this.thisOnvifCamera = thisOnvifCamera;
        this.onvifServicesUrl = onvifServicesUrl;
        this.ipCameraHandler = ipCameraHandler;
        setupListener();
        sendRequest("GetEventProperties");
    }

    public EventsRequest(String requestType, IpCameraHandler ipCameraHandler) {
        this.ipCameraHandler = ipCameraHandler;
        this.requestType = requestType;
    }

    public void sendRequest(String request) {
        requestType = request;
        eventManager.sendOnvifRequest(thisOnvifCamera, this);
        logger.debug("Onvif sendRequest : {}", request);
    }

    public void eventRecieved(String eventMessage) {
        logger.trace("Onvif event : {}", eventMessage);
        if (eventMessage.contains("Name=\"IsMotion\" Value=\"true\"")) {
            ipCameraHandler.motionDetected(CHANNEL_MOTION_ALARM);
        } else if (eventMessage.contains("Name=\"IsMotion\" Value=\"false\"")) {
            ipCameraHandler.noMotionDetected(CHANNEL_MOTION_ALARM);
        }
    }

    private void setupListener() {
        eventManager.setOnvifResponseListener(new OnvifResponseListener() {
            @Override
            public void onResponse(@Nullable OnvifDevice thisOnvifCamera, @Nullable OnvifResponse response) {
                if (response == null) {
                    return;
                }
                logger.debug("We got a ONVIF EVENT:{}", response.getXml());
                if (response.getXml().contains("GetEventPropertiesResponse")) {
                    // sendRequest("CreatePullPointSubscription");
                    sendRequest("Subscribe");
                } else if (response.getXml().contains("SubscribeResponse")) {
                    sendRequest("CreatePullPointSubscription");
                } else if (response.getXml().contains("CreatePullPointSubscriptionResponse")) {
                    eventAddress = searchString(response.getXml(), "Address>");
                    logger.debug("address is {}", eventAddress);
                    sendRequest("PullMessages");
                }
            }

            @Override
            public void onError(@Nullable OnvifDevice thisOnvifCamera, int errorCode, @Nullable String errorMessage) {
                logger.warn("We got a ONVIF EVENT ERROR {}:{}", errorCode, errorMessage);
            }
        });
    }

    @Override
    public String getXml() {
        switch (requestType) {
            case "Subscribe":// works
                return "<m:Subscribe xmlns:m=\"http://docs.oasis-open.org/wsn/b-2\" \r\n"
                        + " xmlns:m0=\"http://www.w3.org/2005/08/addressing\">\r\n" + " <m:ConsumerReference>\r\n"
                        + " <m0:Address>\r\n" + "  http://" + ipCameraHandler.hostIp + ":" + ipCameraHandler.serverPort
                        + "/OnvifEvent\r\n" + " </m0:Address>\r\n" + " </m:ConsumerReference>\r\n" + "</m:Subscribe>";

            case "CreatePullPointSubscription":// works
                return "<CreatePullPointSubscription xmlns=\"http://www.onvif.org/ver10/events/wsdl\"><InitialTerminationTime>PT1M</InitialTerminationTime></CreatePullPointSubscription>";
            case "PullMessages":// needs work, below is only 120 seconds before timeout.
                return "<PullMessages xmlns=\"http://www.onvif.org/ver10/events/wsdl\"><Timeout>PT120S</Timeout><MessageLimit>20</MessageLimit></PullMessages>";
            case "GetEventProperties": // Dahua works.
                return "<GetEventProperties xmlns=\"http://www.onvif.org/ver10/events/wsdl\"><To>" + onvifServicesUrl
                        + "</To></GetEventProperties>";
        }
        return "notfound";
    }

    @Override
    public OnvifType getType() {
        return OnvifType.CUSTOM;
    }

    String searchString(String rawString, String searchedString) {
        String result = "";
        int index = 0;
        index = rawString.indexOf(searchedString);
        if (index != -1) // -1 means "not found"
        {
            result = rawString.substring(index + searchedString.length(), rawString.length());
            index = result.indexOf('<');
            if (index == -1) {
                index = result.indexOf('"');
                if (index == -1) {
                    index = result.indexOf('}');
                    if (index == -1) {
                        return result;
                    } else {
                        return result.substring(0, index);
                    }
                } else {
                    return result.substring(0, index);
                }
            } else {
                result = result.substring(0, index);
                index = result.indexOf('"');
                if (index == -1) {
                    return result;
                } else {
                    return result.substring(0, index);
                }
            }
        }
        return "";
    }
}
