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

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.teletask.onvif.models.OnvifMediaProfile;
import be.teletask.onvif.models.OnvifType;
import be.teletask.onvif.requests.OnvifRequest;

/**
 * The {@link GetSnapshotUri} is responsible for handling onvif snapshot uri commands.
 *
 * @author Matthew Skinner - Initial contribution
 */

@NonNullByDefault
public class GetSnapshotUri implements OnvifRequest {
    public final Logger logger = LoggerFactory.getLogger(getClass());
    String profileToken = "1";

    public GetSnapshotUri() {

    }

    public GetSnapshotUri(OnvifMediaProfile onvifMediaProfile) {
        profileToken = onvifMediaProfile.getToken();
    }

    @Override
    public String getXml() {
        return "<GetSnapshotUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><ProfileToken>" + profileToken
                + "</ProfileToken></GetSnapshotUri>";
    }

    @Override
    public OnvifType getType() {
        return OnvifType.CUSTOM;
    }

    public static String getParsedResult(String result) {
        int beginIndex = result.indexOf(":Uri>"); // 8 char long
        int endIndex = result.indexOf("</", beginIndex);
        if (beginIndex >= 0 && endIndex >= 0) {
            return result.substring(beginIndex + 5, endIndex);
        } else {
            return "SnapshotUriError";
        }
    }
}