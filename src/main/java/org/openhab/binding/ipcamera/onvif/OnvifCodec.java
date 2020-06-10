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
import org.eclipse.jdt.annotation.Nullable;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;

/**
 * The {@link OnvifCodec} is used by Netty to decode Onvif traffic into message Strings.
 *
 *
 * @author Matthew Skinner - Initial contribution
 */
@NonNullByDefault
public class OnvifCodec extends ChannelDuplexHandler {
    String incomingMessage = "";
    OnvifConnection onvifConnection;

    OnvifCodec(OnvifConnection onvifConnection) {
        this.onvifConnection = onvifConnection;
    }

    @Override
    public void channelRead(@Nullable ChannelHandlerContext ctx, @Nullable Object msg) throws Exception {
        if (msg == null) {
            return;
        }
        try {
            if (msg instanceof HttpContent) {
                HttpContent content = (HttpContent) msg;
                incomingMessage += content.content().toString(CharsetUtil.UTF_8);
            }
            if (msg instanceof LastHttpContent) {
                onvifConnection.processReply(incomingMessage);
                incomingMessage = "";
            }
        } finally {
            ReferenceCountUtil.release(msg);
        }
    }

    @Override
    public void exceptionCaught(@Nullable ChannelHandlerContext ctx, @Nullable Throwable cause) {
    }
}
