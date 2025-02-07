/* eslint-disable */
import Long from "long";
import _m0 from "protobufjs/minimal";
import {
  AudioCodec,
  audioCodecFromJSON,
  audioCodecToJSON,
  TrackInfo,
  TrackSource,
  trackSourceFromJSON,
  trackSourceToJSON,
  VideoCodec,
  videoCodecFromJSON,
  videoCodecToJSON,
  VideoLayer,
} from "./livekit_models";

export const protobufPackage = "livekit";

export enum IngressInput {
  RTMP_INPUT = 0,
  WHIP_INPUT = 1,
  /** URL_INPUT - Pull from the provided URL. Only HTTP url are supported, serving either a single media file or a HLS stream */
  URL_INPUT = 2,
  UNRECOGNIZED = -1,
}

export function ingressInputFromJSON(object: any): IngressInput {
  switch (object) {
    case 0:
    case "RTMP_INPUT":
      return IngressInput.RTMP_INPUT;
    case 1:
    case "WHIP_INPUT":
      return IngressInput.WHIP_INPUT;
    case 2:
    case "URL_INPUT":
      return IngressInput.URL_INPUT;
    case -1:
    case "UNRECOGNIZED":
    default:
      return IngressInput.UNRECOGNIZED;
  }
}

export function ingressInputToJSON(object: IngressInput): string {
  switch (object) {
    case IngressInput.RTMP_INPUT:
      return "RTMP_INPUT";
    case IngressInput.WHIP_INPUT:
      return "WHIP_INPUT";
    case IngressInput.URL_INPUT:
      return "URL_INPUT";
    case IngressInput.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum IngressAudioEncodingPreset {
  /** OPUS_STEREO_96KBPS - OPUS, 2 channels, 96kbps */
  OPUS_STEREO_96KBPS = 0,
  /** OPUS_MONO_64KBS - OPUS, 1 channel, 64kbps */
  OPUS_MONO_64KBS = 1,
  UNRECOGNIZED = -1,
}

export function ingressAudioEncodingPresetFromJSON(object: any): IngressAudioEncodingPreset {
  switch (object) {
    case 0:
    case "OPUS_STEREO_96KBPS":
      return IngressAudioEncodingPreset.OPUS_STEREO_96KBPS;
    case 1:
    case "OPUS_MONO_64KBS":
      return IngressAudioEncodingPreset.OPUS_MONO_64KBS;
    case -1:
    case "UNRECOGNIZED":
    default:
      return IngressAudioEncodingPreset.UNRECOGNIZED;
  }
}

export function ingressAudioEncodingPresetToJSON(object: IngressAudioEncodingPreset): string {
  switch (object) {
    case IngressAudioEncodingPreset.OPUS_STEREO_96KBPS:
      return "OPUS_STEREO_96KBPS";
    case IngressAudioEncodingPreset.OPUS_MONO_64KBS:
      return "OPUS_MONO_64KBS";
    case IngressAudioEncodingPreset.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export enum IngressVideoEncodingPreset {
  /** H264_720P_30FPS_3_LAYERS - 1280x720,  30fps, 1900kbps main layer, 3 layers total */
  H264_720P_30FPS_3_LAYERS = 0,
  /** H264_1080P_30FPS_3_LAYERS - 1980x1080, 30fps, 3500kbps main layer, 3 layers total */
  H264_1080P_30FPS_3_LAYERS = 1,
  /** H264_540P_25FPS_2_LAYERS - 960x540,  25fps, 1000kbps  main layer, 2 layers total */
  H264_540P_25FPS_2_LAYERS = 2,
  /** H264_720P_30FPS_1_LAYER - 1280x720,  30fps, 1900kbps, no simulcast */
  H264_720P_30FPS_1_LAYER = 3,
  /** H264_1080P_30FPS_1_LAYER - 1980x1080, 30fps, 3500kbps, no simulcast */
  H264_1080P_30FPS_1_LAYER = 4,
  /** H264_720P_30FPS_3_LAYERS_HIGH_MOTION - 1280x720,  30fps, 2500kbps main layer, 3 layers total, higher bitrate for high motion, harder to encode content */
  H264_720P_30FPS_3_LAYERS_HIGH_MOTION = 5,
  /** H264_1080P_30FPS_3_LAYERS_HIGH_MOTION - 1980x1080, 30fps, 4500kbps main layer, 3 layers total, higher bitrate for high motion, harder to encode content */
  H264_1080P_30FPS_3_LAYERS_HIGH_MOTION = 6,
  /** H264_540P_25FPS_2_LAYERS_HIGH_MOTION - 960x540,  25fps, 1300kbps  main layer, 2 layers total, higher bitrate for high motion, harder to encode content */
  H264_540P_25FPS_2_LAYERS_HIGH_MOTION = 7,
  /** H264_720P_30FPS_1_LAYER_HIGH_MOTION - 1280x720,  30fps, 2500kbps, no simulcast, higher bitrate for high motion, harder to encode content */
  H264_720P_30FPS_1_LAYER_HIGH_MOTION = 8,
  /** H264_1080P_30FPS_1_LAYER_HIGH_MOTION - 1980x1080, 30fps, 4500kbps, no simulcast, higher bitrate for high motion, harder to encode content */
  H264_1080P_30FPS_1_LAYER_HIGH_MOTION = 9,
  UNRECOGNIZED = -1,
}

export function ingressVideoEncodingPresetFromJSON(object: any): IngressVideoEncodingPreset {
  switch (object) {
    case 0:
    case "H264_720P_30FPS_3_LAYERS":
      return IngressVideoEncodingPreset.H264_720P_30FPS_3_LAYERS;
    case 1:
    case "H264_1080P_30FPS_3_LAYERS":
      return IngressVideoEncodingPreset.H264_1080P_30FPS_3_LAYERS;
    case 2:
    case "H264_540P_25FPS_2_LAYERS":
      return IngressVideoEncodingPreset.H264_540P_25FPS_2_LAYERS;
    case 3:
    case "H264_720P_30FPS_1_LAYER":
      return IngressVideoEncodingPreset.H264_720P_30FPS_1_LAYER;
    case 4:
    case "H264_1080P_30FPS_1_LAYER":
      return IngressVideoEncodingPreset.H264_1080P_30FPS_1_LAYER;
    case 5:
    case "H264_720P_30FPS_3_LAYERS_HIGH_MOTION":
      return IngressVideoEncodingPreset.H264_720P_30FPS_3_LAYERS_HIGH_MOTION;
    case 6:
    case "H264_1080P_30FPS_3_LAYERS_HIGH_MOTION":
      return IngressVideoEncodingPreset.H264_1080P_30FPS_3_LAYERS_HIGH_MOTION;
    case 7:
    case "H264_540P_25FPS_2_LAYERS_HIGH_MOTION":
      return IngressVideoEncodingPreset.H264_540P_25FPS_2_LAYERS_HIGH_MOTION;
    case 8:
    case "H264_720P_30FPS_1_LAYER_HIGH_MOTION":
      return IngressVideoEncodingPreset.H264_720P_30FPS_1_LAYER_HIGH_MOTION;
    case 9:
    case "H264_1080P_30FPS_1_LAYER_HIGH_MOTION":
      return IngressVideoEncodingPreset.H264_1080P_30FPS_1_LAYER_HIGH_MOTION;
    case -1:
    case "UNRECOGNIZED":
    default:
      return IngressVideoEncodingPreset.UNRECOGNIZED;
  }
}

export function ingressVideoEncodingPresetToJSON(object: IngressVideoEncodingPreset): string {
  switch (object) {
    case IngressVideoEncodingPreset.H264_720P_30FPS_3_LAYERS:
      return "H264_720P_30FPS_3_LAYERS";
    case IngressVideoEncodingPreset.H264_1080P_30FPS_3_LAYERS:
      return "H264_1080P_30FPS_3_LAYERS";
    case IngressVideoEncodingPreset.H264_540P_25FPS_2_LAYERS:
      return "H264_540P_25FPS_2_LAYERS";
    case IngressVideoEncodingPreset.H264_720P_30FPS_1_LAYER:
      return "H264_720P_30FPS_1_LAYER";
    case IngressVideoEncodingPreset.H264_1080P_30FPS_1_LAYER:
      return "H264_1080P_30FPS_1_LAYER";
    case IngressVideoEncodingPreset.H264_720P_30FPS_3_LAYERS_HIGH_MOTION:
      return "H264_720P_30FPS_3_LAYERS_HIGH_MOTION";
    case IngressVideoEncodingPreset.H264_1080P_30FPS_3_LAYERS_HIGH_MOTION:
      return "H264_1080P_30FPS_3_LAYERS_HIGH_MOTION";
    case IngressVideoEncodingPreset.H264_540P_25FPS_2_LAYERS_HIGH_MOTION:
      return "H264_540P_25FPS_2_LAYERS_HIGH_MOTION";
    case IngressVideoEncodingPreset.H264_720P_30FPS_1_LAYER_HIGH_MOTION:
      return "H264_720P_30FPS_1_LAYER_HIGH_MOTION";
    case IngressVideoEncodingPreset.H264_1080P_30FPS_1_LAYER_HIGH_MOTION:
      return "H264_1080P_30FPS_1_LAYER_HIGH_MOTION";
    case IngressVideoEncodingPreset.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export interface CreateIngressRequest {
  inputType?:
    | IngressInput
    | undefined;
  /** Where to pull media from, only for URL input type */
  url?:
    | string
    | undefined;
  /** User provided identifier for the ingress */
  name?:
    | string
    | undefined;
  /** room to publish to */
  roomName?:
    | string
    | undefined;
  /** publish as participant */
  participantIdentity?:
    | string
    | undefined;
  /** name of publishing participant (used for display only) */
  participantName?:
    | string
    | undefined;
  /** whether to pass through the incoming media without transcoding, only compatible with some input types */
  bypassTranscoding?: boolean | undefined;
  audio?: IngressAudioOptions | undefined;
  video?: IngressVideoOptions | undefined;
}

export interface IngressAudioOptions {
  name?: string | undefined;
  source?: TrackSource | undefined;
  preset?: IngressAudioEncodingPreset | undefined;
  options?: IngressAudioEncodingOptions | undefined;
}

export interface IngressVideoOptions {
  name?: string | undefined;
  source?: TrackSource | undefined;
  preset?: IngressVideoEncodingPreset | undefined;
  options?: IngressVideoEncodingOptions | undefined;
}

export interface IngressAudioEncodingOptions {
  /** desired audio codec to publish to room */
  audioCodec?: AudioCodec | undefined;
  bitrate?: number | undefined;
  disableDtx?: boolean | undefined;
  channels?: number | undefined;
}

export interface IngressVideoEncodingOptions {
  /** desired codec to publish to room */
  videoCodec?: VideoCodec | undefined;
  frameRate?:
    | number
    | undefined;
  /** simulcast layers to publish, when empty, should usually be set to layers at 1/2 and 1/4 of the dimensions */
  layers?: VideoLayer[] | undefined;
}

export interface IngressInfo {
  ingressId?: string | undefined;
  name?: string | undefined;
  streamKey?:
    | string
    | undefined;
  /** URL to point the encoder to for push (RTMP, WHIP), or location to pull media from for pull (URL) */
  url?:
    | string
    | undefined;
  /**
   * for RTMP input, it'll be a rtmp:// URL
   * for FILE input, it'll be a http:// URL
   * for SRT input, it'll be a srt:// URL
   */
  inputType?: IngressInput | undefined;
  bypassTranscoding?: boolean | undefined;
  audio?: IngressAudioOptions | undefined;
  video?: IngressVideoOptions | undefined;
  roomName?: string | undefined;
  participantIdentity?: string | undefined;
  participantName?: string | undefined;
  reusable?:
    | boolean
    | undefined;
  /** Description of error/stream non compliance and debug info for publisher otherwise (received bitrate, resolution, bandwidth) */
  state?: IngressState | undefined;
}

export interface IngressState {
  status?:
    | IngressState_Status
    | undefined;
  /** Error/non compliance description if any */
  error?: string | undefined;
  video?: InputVideoState | undefined;
  audio?:
    | InputAudioState
    | undefined;
  /** ID of the current/previous room published to */
  roomId?: string | undefined;
  startedAt?: number | undefined;
  endedAt?: number | undefined;
  resourceId?: string | undefined;
  tracks?: TrackInfo[] | undefined;
}

export enum IngressState_Status {
  ENDPOINT_INACTIVE = 0,
  ENDPOINT_BUFFERING = 1,
  ENDPOINT_PUBLISHING = 2,
  ENDPOINT_ERROR = 3,
  ENDPOINT_COMPLETE = 4,
  UNRECOGNIZED = -1,
}

export function ingressState_StatusFromJSON(object: any): IngressState_Status {
  switch (object) {
    case 0:
    case "ENDPOINT_INACTIVE":
      return IngressState_Status.ENDPOINT_INACTIVE;
    case 1:
    case "ENDPOINT_BUFFERING":
      return IngressState_Status.ENDPOINT_BUFFERING;
    case 2:
    case "ENDPOINT_PUBLISHING":
      return IngressState_Status.ENDPOINT_PUBLISHING;
    case 3:
    case "ENDPOINT_ERROR":
      return IngressState_Status.ENDPOINT_ERROR;
    case 4:
    case "ENDPOINT_COMPLETE":
      return IngressState_Status.ENDPOINT_COMPLETE;
    case -1:
    case "UNRECOGNIZED":
    default:
      return IngressState_Status.UNRECOGNIZED;
  }
}

export function ingressState_StatusToJSON(object: IngressState_Status): string {
  switch (object) {
    case IngressState_Status.ENDPOINT_INACTIVE:
      return "ENDPOINT_INACTIVE";
    case IngressState_Status.ENDPOINT_BUFFERING:
      return "ENDPOINT_BUFFERING";
    case IngressState_Status.ENDPOINT_PUBLISHING:
      return "ENDPOINT_PUBLISHING";
    case IngressState_Status.ENDPOINT_ERROR:
      return "ENDPOINT_ERROR";
    case IngressState_Status.ENDPOINT_COMPLETE:
      return "ENDPOINT_COMPLETE";
    case IngressState_Status.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}

export interface InputVideoState {
  mimeType?: string | undefined;
  averageBitrate?: number | undefined;
  width?: number | undefined;
  height?: number | undefined;
  framerate?: number | undefined;
}

export interface InputAudioState {
  mimeType?: string | undefined;
  averageBitrate?: number | undefined;
  channels?: number | undefined;
  sampleRate?: number | undefined;
}

export interface UpdateIngressRequest {
  ingressId?: string | undefined;
  name?: string | undefined;
  roomName?: string | undefined;
  participantIdentity?: string | undefined;
  participantName?: string | undefined;
  bypassTranscoding?: boolean | undefined;
  audio?: IngressAudioOptions | undefined;
  video?: IngressVideoOptions | undefined;
}

export interface ListIngressRequest {
  /** when blank, lists all ingress endpoints */
  roomName?:
    | string
    | undefined;
  /** (optional, filter by ingress ID) */
  ingressId?: string | undefined;
}

export interface ListIngressResponse {
  items?: IngressInfo[] | undefined;
}

export interface DeleteIngressRequest {
  ingressId?: string | undefined;
}

function createBaseCreateIngressRequest(): CreateIngressRequest {
  return {
    inputType: 0,
    url: "",
    name: "",
    roomName: "",
    participantIdentity: "",
    participantName: "",
    bypassTranscoding: false,
    audio: undefined,
    video: undefined,
  };
}

export const CreateIngressRequest = {
  encode(message: CreateIngressRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.inputType !== undefined && message.inputType !== 0) {
      writer.uint32(8).int32(message.inputType);
    }
    if (message.url !== undefined && message.url !== "") {
      writer.uint32(74).string(message.url);
    }
    if (message.name !== undefined && message.name !== "") {
      writer.uint32(18).string(message.name);
    }
    if (message.roomName !== undefined && message.roomName !== "") {
      writer.uint32(26).string(message.roomName);
    }
    if (message.participantIdentity !== undefined && message.participantIdentity !== "") {
      writer.uint32(34).string(message.participantIdentity);
    }
    if (message.participantName !== undefined && message.participantName !== "") {
      writer.uint32(42).string(message.participantName);
    }
    if (message.bypassTranscoding === true) {
      writer.uint32(64).bool(message.bypassTranscoding);
    }
    if (message.audio !== undefined) {
      IngressAudioOptions.encode(message.audio, writer.uint32(50).fork()).ldelim();
    }
    if (message.video !== undefined) {
      IngressVideoOptions.encode(message.video, writer.uint32(58).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): CreateIngressRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseCreateIngressRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.inputType = reader.int32() as any;
          continue;
        case 9:
          if (tag !== 74) {
            break;
          }

          message.url = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.name = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.roomName = reader.string();
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.participantIdentity = reader.string();
          continue;
        case 5:
          if (tag !== 42) {
            break;
          }

          message.participantName = reader.string();
          continue;
        case 8:
          if (tag !== 64) {
            break;
          }

          message.bypassTranscoding = reader.bool();
          continue;
        case 6:
          if (tag !== 50) {
            break;
          }

          message.audio = IngressAudioOptions.decode(reader, reader.uint32());
          continue;
        case 7:
          if (tag !== 58) {
            break;
          }

          message.video = IngressVideoOptions.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): CreateIngressRequest {
    return {
      inputType: isSet(object.inputType) ? ingressInputFromJSON(object.inputType) : 0,
      url: isSet(object.url) ? globalThis.String(object.url) : "",
      name: isSet(object.name) ? globalThis.String(object.name) : "",
      roomName: isSet(object.roomName) ? globalThis.String(object.roomName) : "",
      participantIdentity: isSet(object.participantIdentity) ? globalThis.String(object.participantIdentity) : "",
      participantName: isSet(object.participantName) ? globalThis.String(object.participantName) : "",
      bypassTranscoding: isSet(object.bypassTranscoding) ? globalThis.Boolean(object.bypassTranscoding) : false,
      audio: isSet(object.audio) ? IngressAudioOptions.fromJSON(object.audio) : undefined,
      video: isSet(object.video) ? IngressVideoOptions.fromJSON(object.video) : undefined,
    };
  },

  toJSON(message: CreateIngressRequest): unknown {
    const obj: any = {};
    if (message.inputType !== undefined && message.inputType !== 0) {
      obj.inputType = ingressInputToJSON(message.inputType);
    }
    if (message.url !== undefined && message.url !== "") {
      obj.url = message.url;
    }
    if (message.name !== undefined && message.name !== "") {
      obj.name = message.name;
    }
    if (message.roomName !== undefined && message.roomName !== "") {
      obj.roomName = message.roomName;
    }
    if (message.participantIdentity !== undefined && message.participantIdentity !== "") {
      obj.participantIdentity = message.participantIdentity;
    }
    if (message.participantName !== undefined && message.participantName !== "") {
      obj.participantName = message.participantName;
    }
    if (message.bypassTranscoding === true) {
      obj.bypassTranscoding = message.bypassTranscoding;
    }
    if (message.audio !== undefined) {
      obj.audio = IngressAudioOptions.toJSON(message.audio);
    }
    if (message.video !== undefined) {
      obj.video = IngressVideoOptions.toJSON(message.video);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<CreateIngressRequest>, I>>(base?: I): CreateIngressRequest {
    return CreateIngressRequest.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<CreateIngressRequest>, I>>(object: I): CreateIngressRequest {
    const message = createBaseCreateIngressRequest();
    message.inputType = object.inputType ?? 0;
    message.url = object.url ?? "";
    message.name = object.name ?? "";
    message.roomName = object.roomName ?? "";
    message.participantIdentity = object.participantIdentity ?? "";
    message.participantName = object.participantName ?? "";
    message.bypassTranscoding = object.bypassTranscoding ?? false;
    message.audio = (object.audio !== undefined && object.audio !== null)
      ? IngressAudioOptions.fromPartial(object.audio)
      : undefined;
    message.video = (object.video !== undefined && object.video !== null)
      ? IngressVideoOptions.fromPartial(object.video)
      : undefined;
    return message;
  },
};

function createBaseIngressAudioOptions(): IngressAudioOptions {
  return { name: "", source: 0, preset: undefined, options: undefined };
}

export const IngressAudioOptions = {
  encode(message: IngressAudioOptions, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.name !== undefined && message.name !== "") {
      writer.uint32(10).string(message.name);
    }
    if (message.source !== undefined && message.source !== 0) {
      writer.uint32(16).int32(message.source);
    }
    if (message.preset !== undefined) {
      writer.uint32(24).int32(message.preset);
    }
    if (message.options !== undefined) {
      IngressAudioEncodingOptions.encode(message.options, writer.uint32(34).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): IngressAudioOptions {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseIngressAudioOptions();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.name = reader.string();
          continue;
        case 2:
          if (tag !== 16) {
            break;
          }

          message.source = reader.int32() as any;
          continue;
        case 3:
          if (tag !== 24) {
            break;
          }

          message.preset = reader.int32() as any;
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.options = IngressAudioEncodingOptions.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): IngressAudioOptions {
    return {
      name: isSet(object.name) ? globalThis.String(object.name) : "",
      source: isSet(object.source) ? trackSourceFromJSON(object.source) : 0,
      preset: isSet(object.preset) ? ingressAudioEncodingPresetFromJSON(object.preset) : undefined,
      options: isSet(object.options) ? IngressAudioEncodingOptions.fromJSON(object.options) : undefined,
    };
  },

  toJSON(message: IngressAudioOptions): unknown {
    const obj: any = {};
    if (message.name !== undefined && message.name !== "") {
      obj.name = message.name;
    }
    if (message.source !== undefined && message.source !== 0) {
      obj.source = trackSourceToJSON(message.source);
    }
    if (message.preset !== undefined) {
      obj.preset = ingressAudioEncodingPresetToJSON(message.preset);
    }
    if (message.options !== undefined) {
      obj.options = IngressAudioEncodingOptions.toJSON(message.options);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<IngressAudioOptions>, I>>(base?: I): IngressAudioOptions {
    return IngressAudioOptions.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<IngressAudioOptions>, I>>(object: I): IngressAudioOptions {
    const message = createBaseIngressAudioOptions();
    message.name = object.name ?? "";
    message.source = object.source ?? 0;
    message.preset = object.preset ?? undefined;
    message.options = (object.options !== undefined && object.options !== null)
      ? IngressAudioEncodingOptions.fromPartial(object.options)
      : undefined;
    return message;
  },
};

function createBaseIngressVideoOptions(): IngressVideoOptions {
  return { name: "", source: 0, preset: undefined, options: undefined };
}

export const IngressVideoOptions = {
  encode(message: IngressVideoOptions, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.name !== undefined && message.name !== "") {
      writer.uint32(10).string(message.name);
    }
    if (message.source !== undefined && message.source !== 0) {
      writer.uint32(16).int32(message.source);
    }
    if (message.preset !== undefined) {
      writer.uint32(24).int32(message.preset);
    }
    if (message.options !== undefined) {
      IngressVideoEncodingOptions.encode(message.options, writer.uint32(34).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): IngressVideoOptions {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseIngressVideoOptions();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.name = reader.string();
          continue;
        case 2:
          if (tag !== 16) {
            break;
          }

          message.source = reader.int32() as any;
          continue;
        case 3:
          if (tag !== 24) {
            break;
          }

          message.preset = reader.int32() as any;
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.options = IngressVideoEncodingOptions.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): IngressVideoOptions {
    return {
      name: isSet(object.name) ? globalThis.String(object.name) : "",
      source: isSet(object.source) ? trackSourceFromJSON(object.source) : 0,
      preset: isSet(object.preset) ? ingressVideoEncodingPresetFromJSON(object.preset) : undefined,
      options: isSet(object.options) ? IngressVideoEncodingOptions.fromJSON(object.options) : undefined,
    };
  },

  toJSON(message: IngressVideoOptions): unknown {
    const obj: any = {};
    if (message.name !== undefined && message.name !== "") {
      obj.name = message.name;
    }
    if (message.source !== undefined && message.source !== 0) {
      obj.source = trackSourceToJSON(message.source);
    }
    if (message.preset !== undefined) {
      obj.preset = ingressVideoEncodingPresetToJSON(message.preset);
    }
    if (message.options !== undefined) {
      obj.options = IngressVideoEncodingOptions.toJSON(message.options);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<IngressVideoOptions>, I>>(base?: I): IngressVideoOptions {
    return IngressVideoOptions.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<IngressVideoOptions>, I>>(object: I): IngressVideoOptions {
    const message = createBaseIngressVideoOptions();
    message.name = object.name ?? "";
    message.source = object.source ?? 0;
    message.preset = object.preset ?? undefined;
    message.options = (object.options !== undefined && object.options !== null)
      ? IngressVideoEncodingOptions.fromPartial(object.options)
      : undefined;
    return message;
  },
};

function createBaseIngressAudioEncodingOptions(): IngressAudioEncodingOptions {
  return { audioCodec: 0, bitrate: 0, disableDtx: false, channels: 0 };
}

export const IngressAudioEncodingOptions = {
  encode(message: IngressAudioEncodingOptions, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.audioCodec !== undefined && message.audioCodec !== 0) {
      writer.uint32(8).int32(message.audioCodec);
    }
    if (message.bitrate !== undefined && message.bitrate !== 0) {
      writer.uint32(16).uint32(message.bitrate);
    }
    if (message.disableDtx === true) {
      writer.uint32(24).bool(message.disableDtx);
    }
    if (message.channels !== undefined && message.channels !== 0) {
      writer.uint32(32).uint32(message.channels);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): IngressAudioEncodingOptions {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseIngressAudioEncodingOptions();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.audioCodec = reader.int32() as any;
          continue;
        case 2:
          if (tag !== 16) {
            break;
          }

          message.bitrate = reader.uint32();
          continue;
        case 3:
          if (tag !== 24) {
            break;
          }

          message.disableDtx = reader.bool();
          continue;
        case 4:
          if (tag !== 32) {
            break;
          }

          message.channels = reader.uint32();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): IngressAudioEncodingOptions {
    return {
      audioCodec: isSet(object.audioCodec) ? audioCodecFromJSON(object.audioCodec) : 0,
      bitrate: isSet(object.bitrate) ? globalThis.Number(object.bitrate) : 0,
      disableDtx: isSet(object.disableDtx) ? globalThis.Boolean(object.disableDtx) : false,
      channels: isSet(object.channels) ? globalThis.Number(object.channels) : 0,
    };
  },

  toJSON(message: IngressAudioEncodingOptions): unknown {
    const obj: any = {};
    if (message.audioCodec !== undefined && message.audioCodec !== 0) {
      obj.audioCodec = audioCodecToJSON(message.audioCodec);
    }
    if (message.bitrate !== undefined && message.bitrate !== 0) {
      obj.bitrate = Math.round(message.bitrate);
    }
    if (message.disableDtx === true) {
      obj.disableDtx = message.disableDtx;
    }
    if (message.channels !== undefined && message.channels !== 0) {
      obj.channels = Math.round(message.channels);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<IngressAudioEncodingOptions>, I>>(base?: I): IngressAudioEncodingOptions {
    return IngressAudioEncodingOptions.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<IngressAudioEncodingOptions>, I>>(object: I): IngressAudioEncodingOptions {
    const message = createBaseIngressAudioEncodingOptions();
    message.audioCodec = object.audioCodec ?? 0;
    message.bitrate = object.bitrate ?? 0;
    message.disableDtx = object.disableDtx ?? false;
    message.channels = object.channels ?? 0;
    return message;
  },
};

function createBaseIngressVideoEncodingOptions(): IngressVideoEncodingOptions {
  return { videoCodec: 0, frameRate: 0, layers: [] };
}

export const IngressVideoEncodingOptions = {
  encode(message: IngressVideoEncodingOptions, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.videoCodec !== undefined && message.videoCodec !== 0) {
      writer.uint32(8).int32(message.videoCodec);
    }
    if (message.frameRate !== undefined && message.frameRate !== 0) {
      writer.uint32(17).double(message.frameRate);
    }
    if (message.layers !== undefined && message.layers.length !== 0) {
      for (const v of message.layers) {
        VideoLayer.encode(v!, writer.uint32(26).fork()).ldelim();
      }
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): IngressVideoEncodingOptions {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseIngressVideoEncodingOptions();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.videoCodec = reader.int32() as any;
          continue;
        case 2:
          if (tag !== 17) {
            break;
          }

          message.frameRate = reader.double();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.layers!.push(VideoLayer.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): IngressVideoEncodingOptions {
    return {
      videoCodec: isSet(object.videoCodec) ? videoCodecFromJSON(object.videoCodec) : 0,
      frameRate: isSet(object.frameRate) ? globalThis.Number(object.frameRate) : 0,
      layers: globalThis.Array.isArray(object?.layers) ? object.layers.map((e: any) => VideoLayer.fromJSON(e)) : [],
    };
  },

  toJSON(message: IngressVideoEncodingOptions): unknown {
    const obj: any = {};
    if (message.videoCodec !== undefined && message.videoCodec !== 0) {
      obj.videoCodec = videoCodecToJSON(message.videoCodec);
    }
    if (message.frameRate !== undefined && message.frameRate !== 0) {
      obj.frameRate = message.frameRate;
    }
    if (message.layers?.length) {
      obj.layers = message.layers.map((e) => VideoLayer.toJSON(e));
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<IngressVideoEncodingOptions>, I>>(base?: I): IngressVideoEncodingOptions {
    return IngressVideoEncodingOptions.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<IngressVideoEncodingOptions>, I>>(object: I): IngressVideoEncodingOptions {
    const message = createBaseIngressVideoEncodingOptions();
    message.videoCodec = object.videoCodec ?? 0;
    message.frameRate = object.frameRate ?? 0;
    message.layers = object.layers?.map((e) => VideoLayer.fromPartial(e)) || [];
    return message;
  },
};

function createBaseIngressInfo(): IngressInfo {
  return {
    ingressId: "",
    name: "",
    streamKey: "",
    url: "",
    inputType: 0,
    bypassTranscoding: false,
    audio: undefined,
    video: undefined,
    roomName: "",
    participantIdentity: "",
    participantName: "",
    reusable: false,
    state: undefined,
  };
}

export const IngressInfo = {
  encode(message: IngressInfo, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.ingressId !== undefined && message.ingressId !== "") {
      writer.uint32(10).string(message.ingressId);
    }
    if (message.name !== undefined && message.name !== "") {
      writer.uint32(18).string(message.name);
    }
    if (message.streamKey !== undefined && message.streamKey !== "") {
      writer.uint32(26).string(message.streamKey);
    }
    if (message.url !== undefined && message.url !== "") {
      writer.uint32(34).string(message.url);
    }
    if (message.inputType !== undefined && message.inputType !== 0) {
      writer.uint32(40).int32(message.inputType);
    }
    if (message.bypassTranscoding === true) {
      writer.uint32(104).bool(message.bypassTranscoding);
    }
    if (message.audio !== undefined) {
      IngressAudioOptions.encode(message.audio, writer.uint32(50).fork()).ldelim();
    }
    if (message.video !== undefined) {
      IngressVideoOptions.encode(message.video, writer.uint32(58).fork()).ldelim();
    }
    if (message.roomName !== undefined && message.roomName !== "") {
      writer.uint32(66).string(message.roomName);
    }
    if (message.participantIdentity !== undefined && message.participantIdentity !== "") {
      writer.uint32(74).string(message.participantIdentity);
    }
    if (message.participantName !== undefined && message.participantName !== "") {
      writer.uint32(82).string(message.participantName);
    }
    if (message.reusable === true) {
      writer.uint32(88).bool(message.reusable);
    }
    if (message.state !== undefined) {
      IngressState.encode(message.state, writer.uint32(98).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): IngressInfo {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseIngressInfo();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.ingressId = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.name = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.streamKey = reader.string();
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.url = reader.string();
          continue;
        case 5:
          if (tag !== 40) {
            break;
          }

          message.inputType = reader.int32() as any;
          continue;
        case 13:
          if (tag !== 104) {
            break;
          }

          message.bypassTranscoding = reader.bool();
          continue;
        case 6:
          if (tag !== 50) {
            break;
          }

          message.audio = IngressAudioOptions.decode(reader, reader.uint32());
          continue;
        case 7:
          if (tag !== 58) {
            break;
          }

          message.video = IngressVideoOptions.decode(reader, reader.uint32());
          continue;
        case 8:
          if (tag !== 66) {
            break;
          }

          message.roomName = reader.string();
          continue;
        case 9:
          if (tag !== 74) {
            break;
          }

          message.participantIdentity = reader.string();
          continue;
        case 10:
          if (tag !== 82) {
            break;
          }

          message.participantName = reader.string();
          continue;
        case 11:
          if (tag !== 88) {
            break;
          }

          message.reusable = reader.bool();
          continue;
        case 12:
          if (tag !== 98) {
            break;
          }

          message.state = IngressState.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): IngressInfo {
    return {
      ingressId: isSet(object.ingressId) ? globalThis.String(object.ingressId) : "",
      name: isSet(object.name) ? globalThis.String(object.name) : "",
      streamKey: isSet(object.streamKey) ? globalThis.String(object.streamKey) : "",
      url: isSet(object.url) ? globalThis.String(object.url) : "",
      inputType: isSet(object.inputType) ? ingressInputFromJSON(object.inputType) : 0,
      bypassTranscoding: isSet(object.bypassTranscoding) ? globalThis.Boolean(object.bypassTranscoding) : false,
      audio: isSet(object.audio) ? IngressAudioOptions.fromJSON(object.audio) : undefined,
      video: isSet(object.video) ? IngressVideoOptions.fromJSON(object.video) : undefined,
      roomName: isSet(object.roomName) ? globalThis.String(object.roomName) : "",
      participantIdentity: isSet(object.participantIdentity) ? globalThis.String(object.participantIdentity) : "",
      participantName: isSet(object.participantName) ? globalThis.String(object.participantName) : "",
      reusable: isSet(object.reusable) ? globalThis.Boolean(object.reusable) : false,
      state: isSet(object.state) ? IngressState.fromJSON(object.state) : undefined,
    };
  },

  toJSON(message: IngressInfo): unknown {
    const obj: any = {};
    if (message.ingressId !== undefined && message.ingressId !== "") {
      obj.ingressId = message.ingressId;
    }
    if (message.name !== undefined && message.name !== "") {
      obj.name = message.name;
    }
    if (message.streamKey !== undefined && message.streamKey !== "") {
      obj.streamKey = message.streamKey;
    }
    if (message.url !== undefined && message.url !== "") {
      obj.url = message.url;
    }
    if (message.inputType !== undefined && message.inputType !== 0) {
      obj.inputType = ingressInputToJSON(message.inputType);
    }
    if (message.bypassTranscoding === true) {
      obj.bypassTranscoding = message.bypassTranscoding;
    }
    if (message.audio !== undefined) {
      obj.audio = IngressAudioOptions.toJSON(message.audio);
    }
    if (message.video !== undefined) {
      obj.video = IngressVideoOptions.toJSON(message.video);
    }
    if (message.roomName !== undefined && message.roomName !== "") {
      obj.roomName = message.roomName;
    }
    if (message.participantIdentity !== undefined && message.participantIdentity !== "") {
      obj.participantIdentity = message.participantIdentity;
    }
    if (message.participantName !== undefined && message.participantName !== "") {
      obj.participantName = message.participantName;
    }
    if (message.reusable === true) {
      obj.reusable = message.reusable;
    }
    if (message.state !== undefined) {
      obj.state = IngressState.toJSON(message.state);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<IngressInfo>, I>>(base?: I): IngressInfo {
    return IngressInfo.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<IngressInfo>, I>>(object: I): IngressInfo {
    const message = createBaseIngressInfo();
    message.ingressId = object.ingressId ?? "";
    message.name = object.name ?? "";
    message.streamKey = object.streamKey ?? "";
    message.url = object.url ?? "";
    message.inputType = object.inputType ?? 0;
    message.bypassTranscoding = object.bypassTranscoding ?? false;
    message.audio = (object.audio !== undefined && object.audio !== null)
      ? IngressAudioOptions.fromPartial(object.audio)
      : undefined;
    message.video = (object.video !== undefined && object.video !== null)
      ? IngressVideoOptions.fromPartial(object.video)
      : undefined;
    message.roomName = object.roomName ?? "";
    message.participantIdentity = object.participantIdentity ?? "";
    message.participantName = object.participantName ?? "";
    message.reusable = object.reusable ?? false;
    message.state = (object.state !== undefined && object.state !== null)
      ? IngressState.fromPartial(object.state)
      : undefined;
    return message;
  },
};

function createBaseIngressState(): IngressState {
  return {
    status: 0,
    error: "",
    video: undefined,
    audio: undefined,
    roomId: "",
    startedAt: 0,
    endedAt: 0,
    resourceId: "",
    tracks: [],
  };
}

export const IngressState = {
  encode(message: IngressState, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.status !== undefined && message.status !== 0) {
      writer.uint32(8).int32(message.status);
    }
    if (message.error !== undefined && message.error !== "") {
      writer.uint32(18).string(message.error);
    }
    if (message.video !== undefined) {
      InputVideoState.encode(message.video, writer.uint32(26).fork()).ldelim();
    }
    if (message.audio !== undefined) {
      InputAudioState.encode(message.audio, writer.uint32(34).fork()).ldelim();
    }
    if (message.roomId !== undefined && message.roomId !== "") {
      writer.uint32(42).string(message.roomId);
    }
    if (message.startedAt !== undefined && message.startedAt !== 0) {
      writer.uint32(56).int64(message.startedAt);
    }
    if (message.endedAt !== undefined && message.endedAt !== 0) {
      writer.uint32(64).int64(message.endedAt);
    }
    if (message.resourceId !== undefined && message.resourceId !== "") {
      writer.uint32(74).string(message.resourceId);
    }
    if (message.tracks !== undefined && message.tracks.length !== 0) {
      for (const v of message.tracks) {
        TrackInfo.encode(v!, writer.uint32(50).fork()).ldelim();
      }
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): IngressState {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseIngressState();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 8) {
            break;
          }

          message.status = reader.int32() as any;
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.error = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.video = InputVideoState.decode(reader, reader.uint32());
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.audio = InputAudioState.decode(reader, reader.uint32());
          continue;
        case 5:
          if (tag !== 42) {
            break;
          }

          message.roomId = reader.string();
          continue;
        case 7:
          if (tag !== 56) {
            break;
          }

          message.startedAt = longToNumber(reader.int64() as Long);
          continue;
        case 8:
          if (tag !== 64) {
            break;
          }

          message.endedAt = longToNumber(reader.int64() as Long);
          continue;
        case 9:
          if (tag !== 74) {
            break;
          }

          message.resourceId = reader.string();
          continue;
        case 6:
          if (tag !== 50) {
            break;
          }

          message.tracks!.push(TrackInfo.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): IngressState {
    return {
      status: isSet(object.status) ? ingressState_StatusFromJSON(object.status) : 0,
      error: isSet(object.error) ? globalThis.String(object.error) : "",
      video: isSet(object.video) ? InputVideoState.fromJSON(object.video) : undefined,
      audio: isSet(object.audio) ? InputAudioState.fromJSON(object.audio) : undefined,
      roomId: isSet(object.roomId) ? globalThis.String(object.roomId) : "",
      startedAt: isSet(object.startedAt) ? globalThis.Number(object.startedAt) : 0,
      endedAt: isSet(object.endedAt) ? globalThis.Number(object.endedAt) : 0,
      resourceId: isSet(object.resourceId) ? globalThis.String(object.resourceId) : "",
      tracks: globalThis.Array.isArray(object?.tracks) ? object.tracks.map((e: any) => TrackInfo.fromJSON(e)) : [],
    };
  },

  toJSON(message: IngressState): unknown {
    const obj: any = {};
    if (message.status !== undefined && message.status !== 0) {
      obj.status = ingressState_StatusToJSON(message.status);
    }
    if (message.error !== undefined && message.error !== "") {
      obj.error = message.error;
    }
    if (message.video !== undefined) {
      obj.video = InputVideoState.toJSON(message.video);
    }
    if (message.audio !== undefined) {
      obj.audio = InputAudioState.toJSON(message.audio);
    }
    if (message.roomId !== undefined && message.roomId !== "") {
      obj.roomId = message.roomId;
    }
    if (message.startedAt !== undefined && message.startedAt !== 0) {
      obj.startedAt = Math.round(message.startedAt);
    }
    if (message.endedAt !== undefined && message.endedAt !== 0) {
      obj.endedAt = Math.round(message.endedAt);
    }
    if (message.resourceId !== undefined && message.resourceId !== "") {
      obj.resourceId = message.resourceId;
    }
    if (message.tracks?.length) {
      obj.tracks = message.tracks.map((e) => TrackInfo.toJSON(e));
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<IngressState>, I>>(base?: I): IngressState {
    return IngressState.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<IngressState>, I>>(object: I): IngressState {
    const message = createBaseIngressState();
    message.status = object.status ?? 0;
    message.error = object.error ?? "";
    message.video = (object.video !== undefined && object.video !== null)
      ? InputVideoState.fromPartial(object.video)
      : undefined;
    message.audio = (object.audio !== undefined && object.audio !== null)
      ? InputAudioState.fromPartial(object.audio)
      : undefined;
    message.roomId = object.roomId ?? "";
    message.startedAt = object.startedAt ?? 0;
    message.endedAt = object.endedAt ?? 0;
    message.resourceId = object.resourceId ?? "";
    message.tracks = object.tracks?.map((e) => TrackInfo.fromPartial(e)) || [];
    return message;
  },
};

function createBaseInputVideoState(): InputVideoState {
  return { mimeType: "", averageBitrate: 0, width: 0, height: 0, framerate: 0 };
}

export const InputVideoState = {
  encode(message: InputVideoState, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.mimeType !== undefined && message.mimeType !== "") {
      writer.uint32(10).string(message.mimeType);
    }
    if (message.averageBitrate !== undefined && message.averageBitrate !== 0) {
      writer.uint32(16).uint32(message.averageBitrate);
    }
    if (message.width !== undefined && message.width !== 0) {
      writer.uint32(24).uint32(message.width);
    }
    if (message.height !== undefined && message.height !== 0) {
      writer.uint32(32).uint32(message.height);
    }
    if (message.framerate !== undefined && message.framerate !== 0) {
      writer.uint32(41).double(message.framerate);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): InputVideoState {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseInputVideoState();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.mimeType = reader.string();
          continue;
        case 2:
          if (tag !== 16) {
            break;
          }

          message.averageBitrate = reader.uint32();
          continue;
        case 3:
          if (tag !== 24) {
            break;
          }

          message.width = reader.uint32();
          continue;
        case 4:
          if (tag !== 32) {
            break;
          }

          message.height = reader.uint32();
          continue;
        case 5:
          if (tag !== 41) {
            break;
          }

          message.framerate = reader.double();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): InputVideoState {
    return {
      mimeType: isSet(object.mimeType) ? globalThis.String(object.mimeType) : "",
      averageBitrate: isSet(object.averageBitrate) ? globalThis.Number(object.averageBitrate) : 0,
      width: isSet(object.width) ? globalThis.Number(object.width) : 0,
      height: isSet(object.height) ? globalThis.Number(object.height) : 0,
      framerate: isSet(object.framerate) ? globalThis.Number(object.framerate) : 0,
    };
  },

  toJSON(message: InputVideoState): unknown {
    const obj: any = {};
    if (message.mimeType !== undefined && message.mimeType !== "") {
      obj.mimeType = message.mimeType;
    }
    if (message.averageBitrate !== undefined && message.averageBitrate !== 0) {
      obj.averageBitrate = Math.round(message.averageBitrate);
    }
    if (message.width !== undefined && message.width !== 0) {
      obj.width = Math.round(message.width);
    }
    if (message.height !== undefined && message.height !== 0) {
      obj.height = Math.round(message.height);
    }
    if (message.framerate !== undefined && message.framerate !== 0) {
      obj.framerate = message.framerate;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<InputVideoState>, I>>(base?: I): InputVideoState {
    return InputVideoState.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<InputVideoState>, I>>(object: I): InputVideoState {
    const message = createBaseInputVideoState();
    message.mimeType = object.mimeType ?? "";
    message.averageBitrate = object.averageBitrate ?? 0;
    message.width = object.width ?? 0;
    message.height = object.height ?? 0;
    message.framerate = object.framerate ?? 0;
    return message;
  },
};

function createBaseInputAudioState(): InputAudioState {
  return { mimeType: "", averageBitrate: 0, channels: 0, sampleRate: 0 };
}

export const InputAudioState = {
  encode(message: InputAudioState, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.mimeType !== undefined && message.mimeType !== "") {
      writer.uint32(10).string(message.mimeType);
    }
    if (message.averageBitrate !== undefined && message.averageBitrate !== 0) {
      writer.uint32(16).uint32(message.averageBitrate);
    }
    if (message.channels !== undefined && message.channels !== 0) {
      writer.uint32(24).uint32(message.channels);
    }
    if (message.sampleRate !== undefined && message.sampleRate !== 0) {
      writer.uint32(32).uint32(message.sampleRate);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): InputAudioState {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseInputAudioState();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.mimeType = reader.string();
          continue;
        case 2:
          if (tag !== 16) {
            break;
          }

          message.averageBitrate = reader.uint32();
          continue;
        case 3:
          if (tag !== 24) {
            break;
          }

          message.channels = reader.uint32();
          continue;
        case 4:
          if (tag !== 32) {
            break;
          }

          message.sampleRate = reader.uint32();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): InputAudioState {
    return {
      mimeType: isSet(object.mimeType) ? globalThis.String(object.mimeType) : "",
      averageBitrate: isSet(object.averageBitrate) ? globalThis.Number(object.averageBitrate) : 0,
      channels: isSet(object.channels) ? globalThis.Number(object.channels) : 0,
      sampleRate: isSet(object.sampleRate) ? globalThis.Number(object.sampleRate) : 0,
    };
  },

  toJSON(message: InputAudioState): unknown {
    const obj: any = {};
    if (message.mimeType !== undefined && message.mimeType !== "") {
      obj.mimeType = message.mimeType;
    }
    if (message.averageBitrate !== undefined && message.averageBitrate !== 0) {
      obj.averageBitrate = Math.round(message.averageBitrate);
    }
    if (message.channels !== undefined && message.channels !== 0) {
      obj.channels = Math.round(message.channels);
    }
    if (message.sampleRate !== undefined && message.sampleRate !== 0) {
      obj.sampleRate = Math.round(message.sampleRate);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<InputAudioState>, I>>(base?: I): InputAudioState {
    return InputAudioState.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<InputAudioState>, I>>(object: I): InputAudioState {
    const message = createBaseInputAudioState();
    message.mimeType = object.mimeType ?? "";
    message.averageBitrate = object.averageBitrate ?? 0;
    message.channels = object.channels ?? 0;
    message.sampleRate = object.sampleRate ?? 0;
    return message;
  },
};

function createBaseUpdateIngressRequest(): UpdateIngressRequest {
  return {
    ingressId: "",
    name: "",
    roomName: "",
    participantIdentity: "",
    participantName: "",
    bypassTranscoding: undefined,
    audio: undefined,
    video: undefined,
  };
}

export const UpdateIngressRequest = {
  encode(message: UpdateIngressRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.ingressId !== undefined && message.ingressId !== "") {
      writer.uint32(10).string(message.ingressId);
    }
    if (message.name !== undefined && message.name !== "") {
      writer.uint32(18).string(message.name);
    }
    if (message.roomName !== undefined && message.roomName !== "") {
      writer.uint32(26).string(message.roomName);
    }
    if (message.participantIdentity !== undefined && message.participantIdentity !== "") {
      writer.uint32(34).string(message.participantIdentity);
    }
    if (message.participantName !== undefined && message.participantName !== "") {
      writer.uint32(42).string(message.participantName);
    }
    if (message.bypassTranscoding !== undefined) {
      writer.uint32(64).bool(message.bypassTranscoding);
    }
    if (message.audio !== undefined) {
      IngressAudioOptions.encode(message.audio, writer.uint32(50).fork()).ldelim();
    }
    if (message.video !== undefined) {
      IngressVideoOptions.encode(message.video, writer.uint32(58).fork()).ldelim();
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): UpdateIngressRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseUpdateIngressRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.ingressId = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.name = reader.string();
          continue;
        case 3:
          if (tag !== 26) {
            break;
          }

          message.roomName = reader.string();
          continue;
        case 4:
          if (tag !== 34) {
            break;
          }

          message.participantIdentity = reader.string();
          continue;
        case 5:
          if (tag !== 42) {
            break;
          }

          message.participantName = reader.string();
          continue;
        case 8:
          if (tag !== 64) {
            break;
          }

          message.bypassTranscoding = reader.bool();
          continue;
        case 6:
          if (tag !== 50) {
            break;
          }

          message.audio = IngressAudioOptions.decode(reader, reader.uint32());
          continue;
        case 7:
          if (tag !== 58) {
            break;
          }

          message.video = IngressVideoOptions.decode(reader, reader.uint32());
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): UpdateIngressRequest {
    return {
      ingressId: isSet(object.ingressId) ? globalThis.String(object.ingressId) : "",
      name: isSet(object.name) ? globalThis.String(object.name) : "",
      roomName: isSet(object.roomName) ? globalThis.String(object.roomName) : "",
      participantIdentity: isSet(object.participantIdentity) ? globalThis.String(object.participantIdentity) : "",
      participantName: isSet(object.participantName) ? globalThis.String(object.participantName) : "",
      bypassTranscoding: isSet(object.bypassTranscoding) ? globalThis.Boolean(object.bypassTranscoding) : undefined,
      audio: isSet(object.audio) ? IngressAudioOptions.fromJSON(object.audio) : undefined,
      video: isSet(object.video) ? IngressVideoOptions.fromJSON(object.video) : undefined,
    };
  },

  toJSON(message: UpdateIngressRequest): unknown {
    const obj: any = {};
    if (message.ingressId !== undefined && message.ingressId !== "") {
      obj.ingressId = message.ingressId;
    }
    if (message.name !== undefined && message.name !== "") {
      obj.name = message.name;
    }
    if (message.roomName !== undefined && message.roomName !== "") {
      obj.roomName = message.roomName;
    }
    if (message.participantIdentity !== undefined && message.participantIdentity !== "") {
      obj.participantIdentity = message.participantIdentity;
    }
    if (message.participantName !== undefined && message.participantName !== "") {
      obj.participantName = message.participantName;
    }
    if (message.bypassTranscoding !== undefined) {
      obj.bypassTranscoding = message.bypassTranscoding;
    }
    if (message.audio !== undefined) {
      obj.audio = IngressAudioOptions.toJSON(message.audio);
    }
    if (message.video !== undefined) {
      obj.video = IngressVideoOptions.toJSON(message.video);
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<UpdateIngressRequest>, I>>(base?: I): UpdateIngressRequest {
    return UpdateIngressRequest.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<UpdateIngressRequest>, I>>(object: I): UpdateIngressRequest {
    const message = createBaseUpdateIngressRequest();
    message.ingressId = object.ingressId ?? "";
    message.name = object.name ?? "";
    message.roomName = object.roomName ?? "";
    message.participantIdentity = object.participantIdentity ?? "";
    message.participantName = object.participantName ?? "";
    message.bypassTranscoding = object.bypassTranscoding ?? undefined;
    message.audio = (object.audio !== undefined && object.audio !== null)
      ? IngressAudioOptions.fromPartial(object.audio)
      : undefined;
    message.video = (object.video !== undefined && object.video !== null)
      ? IngressVideoOptions.fromPartial(object.video)
      : undefined;
    return message;
  },
};

function createBaseListIngressRequest(): ListIngressRequest {
  return { roomName: "", ingressId: "" };
}

export const ListIngressRequest = {
  encode(message: ListIngressRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.roomName !== undefined && message.roomName !== "") {
      writer.uint32(10).string(message.roomName);
    }
    if (message.ingressId !== undefined && message.ingressId !== "") {
      writer.uint32(18).string(message.ingressId);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ListIngressRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseListIngressRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.roomName = reader.string();
          continue;
        case 2:
          if (tag !== 18) {
            break;
          }

          message.ingressId = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ListIngressRequest {
    return {
      roomName: isSet(object.roomName) ? globalThis.String(object.roomName) : "",
      ingressId: isSet(object.ingressId) ? globalThis.String(object.ingressId) : "",
    };
  },

  toJSON(message: ListIngressRequest): unknown {
    const obj: any = {};
    if (message.roomName !== undefined && message.roomName !== "") {
      obj.roomName = message.roomName;
    }
    if (message.ingressId !== undefined && message.ingressId !== "") {
      obj.ingressId = message.ingressId;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<ListIngressRequest>, I>>(base?: I): ListIngressRequest {
    return ListIngressRequest.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<ListIngressRequest>, I>>(object: I): ListIngressRequest {
    const message = createBaseListIngressRequest();
    message.roomName = object.roomName ?? "";
    message.ingressId = object.ingressId ?? "";
    return message;
  },
};

function createBaseListIngressResponse(): ListIngressResponse {
  return { items: [] };
}

export const ListIngressResponse = {
  encode(message: ListIngressResponse, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.items !== undefined && message.items.length !== 0) {
      for (const v of message.items) {
        IngressInfo.encode(v!, writer.uint32(10).fork()).ldelim();
      }
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): ListIngressResponse {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseListIngressResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.items!.push(IngressInfo.decode(reader, reader.uint32()));
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): ListIngressResponse {
    return {
      items: globalThis.Array.isArray(object?.items) ? object.items.map((e: any) => IngressInfo.fromJSON(e)) : [],
    };
  },

  toJSON(message: ListIngressResponse): unknown {
    const obj: any = {};
    if (message.items?.length) {
      obj.items = message.items.map((e) => IngressInfo.toJSON(e));
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<ListIngressResponse>, I>>(base?: I): ListIngressResponse {
    return ListIngressResponse.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<ListIngressResponse>, I>>(object: I): ListIngressResponse {
    const message = createBaseListIngressResponse();
    message.items = object.items?.map((e) => IngressInfo.fromPartial(e)) || [];
    return message;
  },
};

function createBaseDeleteIngressRequest(): DeleteIngressRequest {
  return { ingressId: "" };
}

export const DeleteIngressRequest = {
  encode(message: DeleteIngressRequest, writer: _m0.Writer = _m0.Writer.create()): _m0.Writer {
    if (message.ingressId !== undefined && message.ingressId !== "") {
      writer.uint32(10).string(message.ingressId);
    }
    return writer;
  },

  decode(input: _m0.Reader | Uint8Array, length?: number): DeleteIngressRequest {
    const reader = input instanceof _m0.Reader ? input : _m0.Reader.create(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseDeleteIngressRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          if (tag !== 10) {
            break;
          }

          message.ingressId = reader.string();
          continue;
      }
      if ((tag & 7) === 4 || tag === 0) {
        break;
      }
      reader.skipType(tag & 7);
    }
    return message;
  },

  fromJSON(object: any): DeleteIngressRequest {
    return { ingressId: isSet(object.ingressId) ? globalThis.String(object.ingressId) : "" };
  },

  toJSON(message: DeleteIngressRequest): unknown {
    const obj: any = {};
    if (message.ingressId !== undefined && message.ingressId !== "") {
      obj.ingressId = message.ingressId;
    }
    return obj;
  },

  create<I extends Exact<DeepPartial<DeleteIngressRequest>, I>>(base?: I): DeleteIngressRequest {
    return DeleteIngressRequest.fromPartial(base ?? ({} as any));
  },
  fromPartial<I extends Exact<DeepPartial<DeleteIngressRequest>, I>>(object: I): DeleteIngressRequest {
    const message = createBaseDeleteIngressRequest();
    message.ingressId = object.ingressId ?? "";
    return message;
  },
};

export interface Ingress {
  /** Create a new Ingress */
  CreateIngress(request: CreateIngressRequest): Promise<IngressInfo>;
  /** Update an existing Ingress. Ingress can only be updated when it's in ENDPOINT_WAITING state. */
  UpdateIngress(request: UpdateIngressRequest): Promise<IngressInfo>;
  ListIngress(request: ListIngressRequest): Promise<ListIngressResponse>;
  DeleteIngress(request: DeleteIngressRequest): Promise<IngressInfo>;
}

type Builtin = Date | Function | Uint8Array | string | number | boolean | undefined;

export type DeepPartial<T> = T extends Builtin ? T
  : T extends globalThis.Array<infer U> ? globalThis.Array<DeepPartial<U>>
  : T extends ReadonlyArray<infer U> ? ReadonlyArray<DeepPartial<U>>
  : T extends {} ? { [K in keyof T]?: DeepPartial<T[K]> }
  : Partial<T>;

type KeysOfUnion<T> = T extends T ? keyof T : never;
export type Exact<P, I extends P> = P extends Builtin ? P
  : P & { [K in keyof P]: Exact<P[K], I[K]> } & { [K in Exclude<keyof I, KeysOfUnion<P>>]: never };

function longToNumber(long: Long): number {
  if (long.gt(globalThis.Number.MAX_SAFE_INTEGER)) {
    throw new globalThis.Error("Value is larger than Number.MAX_SAFE_INTEGER");
  }
  return long.toNumber();
}

if (_m0.util.Long !== Long) {
  _m0.util.Long = Long as any;
  _m0.configure();
}

function isSet(value: any): boolean {
  return value !== null && value !== undefined;
}
