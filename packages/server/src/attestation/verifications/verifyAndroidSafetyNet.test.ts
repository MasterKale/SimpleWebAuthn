import base64url from 'base64url';

import verifyAndroidSafetyNet from './verifyAndroidSafetyNet';

import decodeAttestationObject, {
  AttestationStatement,
} from '../../helpers/decodeAttestationObject';
import parseAuthenticatorData from '../../helpers/parseAuthenticatorData';
import toHash from '../../helpers/toHash';
import settingsService from '../../services/settingsService';

const rootCertificates = settingsService.getRootCertificates({
  attestationFormat: 'android-safetynet',
});

let authData: Buffer;
let attStmt: AttestationStatement;
let clientDataHash: Buffer;
let aaguid: Buffer;

beforeEach(() => {
  const { attestationObject, clientDataJSON } = attestationAndroidSafetyNet.response;
  const decodedAttestationObject = decodeAttestationObject(base64url.toBuffer(attestationObject));

  authData = decodedAttestationObject.authData;
  attStmt = decodedAttestationObject.attStmt;
  clientDataHash = toHash(base64url.toBuffer(clientDataJSON));

  const parsedAuthData = parseAuthenticatorData(authData);
  aaguid = parsedAuthData.aaguid!;
});

/**
 * We need to use the `verifyTimestampMS` escape hatch until I can figure out how to generate a
 * signature after modifying the payload with a `timestampMs` we can dynamically set
 */
test('should verify Android SafetyNet attestation', async () => {
  const verified = await verifyAndroidSafetyNet({
    attStmt,
    authData,
    clientDataHash,
    verifyTimestampMS: false,
    aaguid,
    rootCertificates,
  });

  expect(verified).toEqual(true);
});

test('should throw error when timestamp is not within one minute of now', async () => {
  await expect(
    verifyAndroidSafetyNet({
      attStmt,
      authData,
      clientDataHash,
      aaguid,
      rootCertificates,
    }),
  ).rejects.toThrow(/has expired/i);
});

test('should validate response with cert path completed with GlobalSign R1 root cert', async () => {
  const { attestationObject, clientDataJSON } = safetyNetUsingGSR1RootCert.response;
  const decodedAttestationObject = decodeAttestationObject(base64url.toBuffer(attestationObject));

  const _authData = decodedAttestationObject.authData;
  const _attStmt = decodedAttestationObject.attStmt;
  const _clientDataHash = toHash(base64url.toBuffer(clientDataJSON));

  const parsedAuthData = parseAuthenticatorData(_authData);
  const _aaguid = parsedAuthData.aaguid!;

  const verified = await verifyAndroidSafetyNet({
    attStmt: _attStmt,
    authData: _authData,
    clientDataHash: _clientDataHash,
    verifyTimestampMS: false,
    aaguid: _aaguid,
    rootCertificates,
  });

  expect(verified).toEqual(true);
});

const attestationAndroidSafetyNet = {
  id: 'AQy9gSmVYQXGuzd492rA2qEqwN7SYE_xOCjduU4QVagRwnX30mbfW75Lu4TwXHe-gc1O2PnJF7JVJA9dyJm83Xs',
  rawId: 'AQy9gSmVYQXGuzd492rA2qEqwN7SYE_xOCjduU4QVagRwnX30mbfW75Lu4TwXHe-gc1O2PnJF7JVJA9dyJm83Xs',
  response: {
    attestationObject:
      'o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDE3MTIyMDM3aHJlc' +
      '3BvbnNlWRS9ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHYTJwRFEwSkljV2RCZDBsQ1FXZEpVV' +
      'kpZY205T01GcFBaRkpyUWtGQlFVRkJRVkIxYm5wQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFSkRUVkZ6ZDBOU' +
      'ldVUldVVkZIUlhkS1ZsVjZSV1ZOUW5kSFFURlZSVU5vVFZaU01qbDJXako0YkVsR1VubGtXRTR3U1VaT2JHTnVXb' +
      'kJaTWxaNlRWSk5kMFZSV1VSV1VWRkVSWGR3U0ZaR1RXZFJNRVZuVFZVNGVFMUNORmhFVkVVMFRWUkJlRTFFUVROT' +
      'lZHc3dUbFp2V0VSVVJUVk5WRUYzVDFSQk0wMVVhekJPVm05M1lrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaEZla' +
      '0ZTUW1kT1ZrSkJaMVJEYTA1b1lrZHNiV0l6U25WaFYwVjRSbXBCVlVKblRsWkNRV05VUkZVeGRtUlhOVEJaVjJ4M' +
      'VNVWmFjRnBZWTNoRmVrRlNRbWRPVmtKQmIxUkRhMlIyWWpKa2MxcFRRazFVUlUxNFIzcEJXa0puVGxaQ1FVMVVSV' +
      'zFHTUdSSFZucGtRelZvWW0xU2VXSXliR3RNYlU1MllsUkRRMEZUU1hkRVVWbEtTMjlhU1doMlkwNUJVVVZDUWxGQ' +
      'lJHZG5SVkJCUkVORFFWRnZRMmRuUlVKQlRtcFlhM293WlVzeFUwVTBiU3N2UnpWM1QyOHJXRWRUUlVOeWNXUnVPR' +
      'Gh6UTNCU04yWnpNVFJtU3pCU2FETmFRMWxhVEVaSWNVSnJOa0Z0V2xaM01rczVSa2N3VHpseVVsQmxVVVJKVmxKN' +
      'VJUTXdVWFZ1VXpsMVowaEROR1ZuT1c5MmRrOXRLMUZrV2pKd09UTllhSHAxYmxGRmFGVlhXRU40UVVSSlJVZEtTe' +
      'k5UTW1GQlpucGxPVGxRVEZNeU9XaE1ZMUYxV1ZoSVJHRkROMDlhY1U1dWIzTnBUMGRwWm5NNGRqRnFhVFpJTDNob' +
      '2JIUkRXbVV5YkVvck4wZDFkSHBsZUV0d2VIWndSUzkwV2xObVlsazVNRFZ4VTJ4Q2FEbG1jR293TVRWamFtNVJSb' +
      'XRWYzBGVmQyMUxWa0ZWZFdWVmVqUjBTMk5HU3pSd1pYWk9UR0Y0UlVGc0swOXJhV3hOZEVsWlJHRmpSRFZ1Wld3M' +
      'GVFcHBlWE0wTVROb1lXZHhWekJYYUdnMVJsQXpPV2hIYXpsRkwwSjNVVlJxWVhwVGVFZGtkbGd3YlRaNFJsbG9hQ' +
      'zh5VmsxNVdtcFVORXQ2VUVwRlEwRjNSVUZCWVU5RFFXeG5kMmRuU2xWTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkS' +
      'lJtOUVRVlJDWjA1V1NGTlZSVVJFUVV0Q1oyZHlRbWRGUmtKUlkwUkJWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRV' +
      'TFDTUVkQk1WVmtSR2RSVjBKQ1VYRkNVWGRIVjI5S1FtRXhiMVJMY1hWd2J6UlhObmhVTm1veVJFRm1RbWRPVmtoV' +
      'FRVVkhSRUZYWjBKVFdUQm1hSFZGVDNaUWJTdDRaMjU0YVZGSE5rUnlabEZ1T1V0NlFtdENaMmR5UW1kRlJrSlJZM' +
      'EpCVVZKWlRVWlpkMHAzV1VsTGQxbENRbEZWU0UxQlIwZEhNbWd3WkVoQk5reDVPWFpaTTA1M1RHNUNjbUZUTlc1a' +
      'U1qbHVUREprTUdONlJuWk5WRUZ5UW1kbmNrSm5SVVpDVVdOM1FXOVpabUZJVWpCalJHOTJURE5DY21GVE5XNWlNa' +
      'mx1VERKa2VtTnFTWFpTTVZKVVRWVTRlRXh0VG5sa1JFRmtRbWRPVmtoU1JVVkdha0ZWWjJoS2FHUklVbXhqTTFGM' +
      'VdWYzFhMk50T1hCYVF6VnFZakl3ZDBsUldVUldVakJuUWtKdmQwZEVRVWxDWjFwdVoxRjNRa0ZuU1hkRVFWbExTM' +
      '2RaUWtKQlNGZGxVVWxHUVhwQmRrSm5UbFpJVWpoRlMwUkJiVTFEVTJkSmNVRm5hR2cxYjJSSVVuZFBhVGgyV1ROS' +
      '2MweHVRbkpoVXpWdVlqSTVia3d3WkZWVmVrWlFUVk0xYW1OdGQzZG5aMFZGUW1kdmNrSm5SVVZCWkZvMVFXZFJRM' +
      'EpKU0RGQ1NVaDVRVkJCUVdSM1EydDFVVzFSZEVKb1dVWkpaVGRGTmt4TldqTkJTMUJFVjFsQ1VHdGlNemRxYW1RN' +
      'E1FOTVRVE5qUlVGQlFVRlhXbVJFTTFCTVFVRkJSVUYzUWtsTlJWbERTVkZEVTFwRFYyVk1Tblp6YVZaWE5rTm5LM' +
      'mRxTHpsM1dWUktVbnAxTkVocGNXVTBaVmswWXk5dGVYcHFaMGxvUVV4VFlta3ZWR2g2WTNweGRHbHFNMlJyTTNaa' +
      'VRHTkpWek5NYkRKQ01HODNOVWRSWkdoTmFXZGlRbWRCU0ZWQlZtaFJSMjFwTDFoM2RYcFVPV1ZIT1ZKTVNTdDRNR' +
      'm95ZFdKNVdrVldla0UzTlZOWlZtUmhTakJPTUVGQlFVWnRXRkU1ZWpWQlFVRkNRVTFCVW1wQ1JVRnBRbU5EZDBFN' +
      'WFqZE9WRWRZVURJM09IbzBhSEl2ZFVOSWFVRkdUSGx2UTNFeVN6QXJlVXhTZDBwVlltZEpaMlk0WjBocWRuQjNNb' +
      'TFDTVVWVGFuRXlUMll6UVRCQlJVRjNRMnR1UTJGRlMwWlZlVm8zWmk5UmRFbDNSRkZaU2t0dldrbG9kbU5PUVZGR' +
      'lRFSlJRVVJuWjBWQ1FVazVibFJtVWt0SlYyZDBiRmRzTTNkQ1REVTFSVlJXTm10aGVuTndhRmN4ZVVGak5VUjFiV' +
      'FpZVHpReGExcDZkMG8yTVhkS2JXUlNVbFF2VlhORFNYa3hTMFYwTW1Nd1JXcG5iRzVLUTBZeVpXRjNZMFZYYkV4U' +
      'ldUSllVRXg1Um1wclYxRk9ZbE5vUWpGcE5GY3lUbEpIZWxCb2RETnRNV0kwT1doaWMzUjFXRTAyZEZnMVEzbEZTR' +
      'zVVYURoQ2IyMDBMMWRzUm1sb2VtaG5iamd4Ukd4a2IyZDZMMHN5VlhkTk5sTTJRMEl2VTBWNGEybFdabllyZW1KS' +
      '01ISnFkbWM1TkVGc1pHcFZabFYzYTBrNVZrNU5ha1ZRTldVNGVXUkNNMjlNYkRabmJIQkRaVVkxWkdkbVUxZzBWV' +
      'Gw0TXpWdmFpOUpTV1F6VlVVdlpGQndZaTl4WjBkMmMydG1aR1Y2ZEcxVmRHVXZTMU50Y21sM1kyZFZWMWRsV0daV' +
      'Vlra3plbk5wYTNkYVltdHdiVkpaUzIxcVVHMW9kalJ5YkdsNlIwTkhkRGhRYmpod2NUaE5Na3RFWmk5UU0ydFdiM' +
      '1F6WlRFNFVUMGlMQ0pOU1VsRlUycERRMEY2UzJkQmQwbENRV2RKVGtGbFR6QnRjVWRPYVhGdFFrcFhiRkYxUkVGT' +
      '1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFrMU5VMEYzU0dkWlJGWlJVVXhGZUdSSVlrYzVhVmxYZUZSaFYyUjFTV' +
      'VpLZG1JelVXZFJNRVZuVEZOQ1UwMXFSVlJOUWtWSFFURlZSVU5vVFV0U01uaDJXVzFHYzFVeWJHNWlha1ZVVFVKR' +
      'lIwRXhWVVZCZUUxTFVqSjRkbGx0Um5OVk1teHVZbXBCWlVaM01IaE9la0V5VFZSVmQwMUVRWGRPUkVwaFJuY3dlV' +
      'TFVUlhsTlZGVjNUVVJCZDA1RVNtRk5SVWw0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFTTkhkSVFWbEVWbEZSUzBWN' +
      'FZraGlNamx1WWtkVloxWklTakZqTTFGblZUSldlV1J0YkdwYVdFMTRSWHBCVWtKblRsWkNRVTFVUTJ0a1ZWVjVRa' +
      '1JSVTBGNFZIcEZkMmRuUldsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVUpFZDBGM1oyZEZTMEZ2U1VKQ' +
      'lVVUlJSMDA1UmpGSmRrNHdOWHByVVU4NUszUk9NWEJKVW5aS2VucDVUMVJJVnpWRWVrVmFhRVF5WlZCRGJuWlZRV' +
      'EJSYXpJNFJtZEpRMlpMY1VNNVJXdHpRelJVTW1aWFFsbHJMMnBEWmtNelVqTldXazFrVXk5a1RqUmFTME5GVUZwU' +
      '2NrRjZSSE5wUzFWRWVsSnliVUpDU2pWM2RXUm5lbTVrU1UxWlkweGxMMUpIUjBac05YbFBSRWxMWjJwRmRpOVRTa' +
      '2d2VlV3clpFVmhiSFJPTVRGQ2JYTkxLMlZSYlUxR0t5dEJZM2hIVG1oeU5UbHhUUzg1YVd3M01Va3laRTQ0Umtkb' +
      'VkyUmtkM1ZoWldvMFlsaG9jREJNWTFGQ1ltcDRUV05KTjBwUU1HRk5NMVEwU1N0RWMyRjRiVXRHYzJKcWVtRlVUa' +
      '001ZFhwd1JteG5UMGxuTjNKU01qVjRiM2x1VlhoMk9IWk9iV3R4TjNwa1VFZElXR3Q0VjFrM2IwYzVhaXRLYTFKN' +
      'VFrRkNhemRZY2twbWIzVmpRbHBGY1VaS1NsTlFhemRZUVRCTVMxY3dXVE42Tlc5Nk1rUXdZekYwU2t0M1NFRm5UV' +
      'UpCUVVkcVoyZEZlazFKU1VKTWVrRlBRbWRPVmtoUk9FSkJaamhGUWtGTlEwRlpXWGRJVVZsRVZsSXdiRUpDV1hkR' +
      '1FWbEpTM2RaUWtKUlZVaEJkMFZIUTBOelIwRlJWVVpDZDAxRFRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaa' +
      'mhEUVZGQmQwaFJXVVJXVWpCUFFrSlpSVVpLYWxJclJ6UlJOamdyWWpkSFEyWkhTa0ZpYjA5ME9VTm1NSEpOUWpoS' +
      'FFURlZaRWwzVVZsTlFtRkJSa3AyYVVJeFpHNUlRamRCWVdkaVpWZGlVMkZNWkM5alIxbFpkVTFFVlVkRFEzTkhRV' +
      'kZWUmtKM1JVSkNRMnQzU25wQmJFSm5aM0pDWjBWR1FsRmpkMEZaV1ZwaFNGSXdZMFJ2ZGt3eU9XcGpNMEYxWTBkM' +
      'GNFeHRaSFppTW1OMldqTk9lVTFxUVhsQ1owNVdTRkk0UlV0NlFYQk5RMlZuU21GQmFtaHBSbTlrU0ZKM1QyazRkb' +
      'Gt6U25OTWJrSnlZVk0xYm1JeU9XNU1NbVI2WTJwSmRsb3pUbmxOYVRWcVkyMTNkMUIzV1VSV1VqQm5Ra1JuZDA1c' +
      'VFUQkNaMXB1WjFGM1FrRm5TWGRMYWtGdlFtZG5ja0puUlVaQ1VXTkRRVkpaWTJGSVVqQmpTRTAyVEhrNWQyRXlhM' +
      '1ZhTWpsMlduazVlVnBZUW5aak1td3dZak5LTlV4NlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGS' +
      'GIwRXJUbTV1TnpoNU5uQlNhbVE1V0d4UlYwNWhOMGhVWjJsYUwzSXpVazVIYTIxVmJWbElVRkZ4TmxOamRHazVVR' +
      'VZoYW5aM1VsUXlhVmRVU0ZGeU1ESm1aWE54VDNGQ1dUSkZWRlYzWjFwUksyeHNkRzlPUm5ab2MwODVkSFpDUTA5S' +
      'llYcHdjM2RYUXpsaFNqbDRhblUwZEZkRVVVZzRUbFpWTmxsYVdpOVlkR1ZFVTBkVk9WbDZTbkZRYWxrNGNUTk5SS' +
      'Gh5ZW0xeFpYQkNRMlkxYnpodGR5OTNTalJoTWtjMmVIcFZjalpHWWpaVU9FMWpSRTh5TWxCTVVrdzJkVE5OTkZSN' +
      'mN6TkJNazB4YWpaaWVXdEtXV2s0ZDFkSlVtUkJka3RNVjFwMUwyRjRRbFppZWxsdGNXMTNhMjAxZWt4VFJGYzFia' +
      '2xCU21KRlRFTlJRMXAzVFVnMU5uUXlSSFp4YjJaNGN6WkNRbU5EUmtsYVZWTndlSFUyZURaMFpEQldOMU4yU2tOR' +
      'GIzTnBjbE50U1dGMGFpODVaRk5UVmtSUmFXSmxkRGh4THpkVlN6UjJORnBWVGpnd1lYUnVXbm94ZVdjOVBTSmRmU' +
      'S5leUp1YjI1alpTSTZJbkZyYjB4dE9XSnJUeXNyYzJoMFZITnZheXRqUW1GRmJFcEJXa1pXTUcxRlFqQTVVbWcxV' +
      'TNKWVpGVTlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFOalUwTWpReU5qSTNOek1zSW1Gd2ExQmhZMnRoWjJWT1lXM' +
      'WxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJaXR0Y' +
      '0ZKQ016RjRRemRTYUdsaWN5OWxWbUVyTDNWQ05XNTFaMVVyV0UxRFFXa3plSFZKZGpaMGIwMDlJaXdpWTNSelVIS' +
      'nZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0V' +
      'URGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYT' +
      'nBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC5yUW5Ib2FZVGgxTEU2VVZwaU1lZWFidDdUeWJ3dzdXZk42RzJ5R01tZ' +
      'kVjbTFabjRWalZkenpoY1BqTS1WR052aWl1RGxyZ2VuWEViZ082V05YNlYzc0hHVjN1VGxGMlBuOUZsY3YxWmItS' +
      '2NGVHZUd29iYnY3LUp5VUZzTlhTSnhHZFRTOWxwNU5EdDFnWGJ6OVpORWhzVXI3ajBqbWNyaU9rR29PRzM4MXRSa' +
      '0Vqdk5aa0hpMkF1UDF2MWM4RXg3cEpZc09ISzJxaDlmSHFuSlAzcGowUFc3WThpcDBSTVZaNF9xZzFqc0dMMnZ0O' +
      'G12cEJFMjg5dE1fcnROdm94TWU2aEx0Q1ZkdE9ZRjIzMWMtWVFJd2FEbnZWdDcwYW5XLUZYdUx3R1J5dWhfRlpNM' +
      '3FCSlhhcXdCNjNITk5uMmh5MFRDdHQ4RDdIMmI4MGltWkZRX1FoYXV0aERhdGFYxT3cRxDpwIiyKduonVYyILs59' +
      'yKa_0ZbCmVrGvuaivigRQAAAAC5P9lh8uZGL7EiggAiR954AEEBDL2BKZVhBca7N3j3asDaoSrA3tJgT_E4KN25T' +
      'hBVqBHCdffSZt9bvku7hPBcd76BzU7Y-ckXslUkD13Imbzde6UBAgMmIAEhWCCT4hId3ByJ_agRyznv1xIazx2nl' +
      'VEGyvN7intoZr7C2CJYIKo3XB-cca9aUOLC-xhp3GfhyfTS0hjws5zL_bT_N1AL',
    clientDataJSON:
      'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWDNaV1VHOUZOREpF' +
      'YUMxM2F6Tmlka2h0WVd0MGFWWjJSVmxETFV4M1FsZyIsIm9yaWdpbiI6Imh0dHBzOlwvXC9kZXYuZG9udG5lZWRh' +
      'LnB3IiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiY29tLmFuZHJvaWQuY2hyb21lIn0',
  },
  getClientExtensionResults: () => ({}),
  type: 'public-key',
};
const attestationAndroidSafetyNetChallenge = '_vVPoE42Dh-wk3bvHmaktiVvEYC-LwBX';

const safetyNetUsingGSR1RootCert = {
  id: 'AQsMmnEQ8OxpZxijXBMT4tyamgkqC_3hr18_e8KeK8nG69ijcTaXNKX_CRmYiW0fegPE0N_3NVHEaj_kit7LPNM',
  rawId: 'AQsMmnEQ8OxpZxijXBMT4tyamgkqC_3hr18_e8KeK8nG69ijcTaXNKX_CRmYiW0fegPE0N_3NVHEaj_kit7LPNM',
  response: {
    attestationObject:
      'o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaTIxMjQxODA0NmhyZXNwb25zZVkgcmV5SmhiR2Np' +
      'T2lKU1V6STFOaUlzSW5nMVl5STZXeUpOU1VsR1dIcERRMEpGWldkQmQwbENRV2RKVVdadE9HbFpXbnAxY1RCRlNr' +
      'RkJRVUZCU0RkMVVsUkJUa0puYTNGb2EybEhPWGN3UWtGUmMwWkJSRUpIVFZGemQwTlJXVVJXVVZGSFJYZEtWbFY2' +
      'UldsTlEwRkhRVEZWUlVOb1RWcFNNamwyV2pKNGJFbEdVbmxrV0U0d1NVWk9iR051V25CWk1sWjZTVVY0VFZGNlJW' +
      'Uk5Ra1ZIUVRGVlJVRjRUVXRTTVZKVVNVVk9Ra2xFUmtWT1JFRmxSbmN3ZVUxVVFUTk5WR3Q0VFhwRmVrNUVTbUZH' +
      'ZHpCNVRWUkZkMDFVWTNoTmVrVjZUa1JHWVUxQ01IaEhla0ZhUW1kT1ZrSkJUVlJGYlVZd1pFZFdlbVJETldoaWJW' +
      'SjVZakpzYTB4dFRuWmlWRU5EUVZOSmQwUlJXVXBMYjFwSmFIWmpUa0ZSUlVKQ1VVRkVaMmRGVUVGRVEwTkJVVzlE' +
      'WjJkRlFrRkxaazVUUWxsNE0wMDJTbkpKYVRCTVVVUkdORlZhYUhSemVUZ3lRMjgwVG5aM2NpOUdTVzQzTHpsbksz' +
      'aHpWM3BEV1dkU04xRnpSMjF5ZVVjNWRsQkdja2Q1VVhKRlpHcERVWFZDVTFGVGQyOXZOR2R3YVVocGR6RllibkZH' +
      'Wm5KT1l6SjNURkpQTDFCVWRTdGhhMFpFU1UwMlozVXpaR1JuZDFGWFIwZGFjbFpRZWt0RmFrOTVUbE5HVFVKTU1G' +
      'ZEJTMmwxZFZsQ2RqRTBVWFp1YmxjeFJXdFpZbkZLWkZSb05reFhabVYyWTFkU1N5dFVkRlpoT1hwelIyNUZibWMz' +
      'YTAxUVYxQkNTekJPTUdKUVozaGlOR3B1ZUdGSWNXeE1lSEV2UTJwRWJreHJSRVZrZFdabFZEVlZaM0pzVkc1M09W' +
      'VnRXbTFOZUdGUWRHRXZkbm93WTJnMlpteERkM2xwZG1wSGFqSjRWRWhMVmxsMmJWbHdORlJtVEdjd1kxVk9VRVV4' +
      'WkV0cVRrbGlTMWxEZUZGSlZucHVlSFY0WlhCVVUxWnBXWFZqVUVZMFZuZHVLelpFT1ZwNFVVcEtLeTlsTmt0TVNX' +
      'dERRWGRGUVVGaFQwTkJia0YzWjJkS2MwMUJORWRCTVZWa1JIZEZRaTkzVVVWQmQwbEdiMFJCVkVKblRsWklVMVZG' +
      'UkVSQlMwSm5aM0pDWjBWR1FsRmpSRUZVUVUxQ1owNVdTRkpOUWtGbU9FVkJha0ZCVFVJd1IwRXhWV1JFWjFGWFFr' +
      'SlVUWE5VU1RWeFowRlBVbXRCWkROTlVFd3dOV2cwTm1KdlZsaEVRV1pDWjA1V1NGTk5SVWRFUVZkblFsRnNOR2hu' +
      'VDNOc1pWSnNRM0pzTVVZeVIydEpVR1ZWTjA4MGEycENkRUpuWjNKQ1owVkdRbEZqUWtGUlVtaE5SamgzUzJkWlNV' +
      'dDNXVUpDVVZWSVRVRkhSMGh0YURCa1NFRTJUSGs1ZGxrelRuZE1ia0p5WVZNMWJtSXlPVzVNTW1Rd1kzcEdhMDVI' +
      'YkhWa1JFRjRRbWRuY2tKblJVWkNVV04zUVc5WmJHRklVakJqUkc5MlRETkNjbUZUTlc1aU1qbHVURE5LYkdOSE9I' +
      'WlpNbFo1WkVoTmRsb3pVbnBOVjFFd1RHMVNiR05xUVdSQ1owNVdTRkpGUlVacVFWVm5hRXBvWkVoU2JHTXpVWFZa' +
      'VnpWclkyMDVjRnBETldwaU1qQjNTVkZaUkZaU01HZENRbTkzUjBSQlNVSm5XbTVuVVhkQ1FXZEZkMFJCV1V0TGQx' +
      'bENRa0ZJVjJWUlNVWkJla0V2UW1kT1ZraFNPRVZQUkVFeVRVUlRaMDF4UVhkb2FUVnZaRWhTZDA5cE9IWlpNMHB6' +
      'WTNrMWQyRXlhM1ZhTWpsMlduazVibVJJVFhoYVJGSndZbTVSZGxnd1dsRmpXRVpLVTBka1dVNXFaM1ZaTTBwelRV' +
      'bEpRa0YzV1V0TGQxbENRa0ZJVjJWUlNVVkJaMU5DT1VGVFFqaFJSSFpCU0ZWQldFNTRSR3QyTjIxeE1GWkZjMVky' +
      'WVRGR1ltMUZSR1kzTVdad1NETkxSbnBzVEVwbE5YWmlTRVJ6YjBGQlFVWTJkbmd5VHpGblFVRkNRVTFCVW1wQ1JV' +
      'RnBRa3AxVjFCU2JWSk5kbXBqVkZWd1NXSnlUa3RvT0hONFlrZDRUbEJOWm14aWNuWXhaSGhVYWtwM1EyZEpaMU01' +
      'ZDJkTVZVcGxVWEZNVFZJNFdHVnVSMDVtZVZsb1lYRnNjbEo0ZUUwNGMxQTRWa2x3VVVkVFV6QkJaR2RDT1ZCMlRE' +
      'UnFMeXRKVmxkbmEzZHpSRXR1YkV0S1pWTjJSa1J1WjBwbWVUVnhiREpwV21acFRIY3hkMEZCUVZoeEwwaFpLMHRC' +
      'UVVGRlFYZENTRTFGVlVOSlJESk1NbkpJUW14S2FUbFNSbTlQWmtWQ00yUjRTR1ZJVjFSS2QzTndORFpKWmtscU5t' +
      'OUxTM0JZWWtGcFJVRXlOVk5aUmswNFp6RlVLMGRKVlhKVlRUQjRZMDVVZDJrdmJISnhhRmxyVVUxSEswWnpNbVp0' +
      'Um1SSmQwUlJXVXBMYjFwSmFIWmpUa0ZSUlV4Q1VVRkVaMmRGUWtGRU5qaG1lRWhNZUU5REsxWnNUakZTVGtONVMy' +
      'UlVjV1pJWWxKQlFXUk9XVmczTjBoWEwyMVFRbTVWUXpGb2NtVlVSM2hIZUZOT01VUm9hazF4Tkhwb09GQkRiVEI2' +
      'TDNKQ00zQkVkMmxuYldsTmRtRllVRVZFYXpaRWJHbE5VMFY1WkRCak5ua3dPV2cxVjA1WFRpOWplR3BITDNWUk1E' +
      'SjZSRU12UldrdlptUkZaM1V5TVVobmVITTNRMFZVZFROMFpUWkNiekZTZUM5NFIxRnRLMnRvTlhZd2NIWXJhVmw2' +
      'Y25oVmJFOHZUV1J2YjJsa2VqbENRMWhYT0haeVRVbzJVbk5SVmxKUWVUUjVSbGN2TXpjeU4yeDFSRnBaTUVoME5X' +
      'MUZSa2xLUTNCV1EybENUSE5wZURCd2JWUnNhMXBhZFhSRWFDOHZUV1JOTlVFME56RldRVU14VTBsNGVrTXpUMkYw' +
      'ZEZoV1RGTnRTWFpuZDFoWFlsbzVhekpzZWtwcGVrRnNiRkpMVld0TlRGUmtjMDlFY0RVek0yNVBhMlJXVTFvMlpp' +
      'dEljbkZKYzFSTVRuTTFVVk5MWWtVMGNuaHlkbFpPS3pROUlpd2lUVWxKUm1wRVEwTkJNMU5uUVhkSlFrRm5TVTVC' +
      'WjBOUGMyZEplazV0VjB4YVRUTmliWHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpCUkVKSVRWRnpkME5SV1VSV1VW' +
      'RkhSWGRLVmxWNlJXbE5RMEZIUVRGVlJVTm9UVnBTTWpsMldqSjRiRWxHVW5sa1dFNHdTVVpPYkdOdVduQlpNbFo2' +
      'U1VWNFRWRjZSVlZOUWtsSFFURlZSVUY0VFV4U01WSlVTVVpLZG1JelVXZFZha1YzU0doalRrMXFRWGRQUkVWNlRV' +
      'UkJkMDFFVVhsWGFHTk9UV3BqZDA5VVRYZE5SRUYzVFVSUmVWZHFRa2ROVVhOM1ExRlpSRlpSVVVkRmQwcFdWWHBG' +
      'YVUxRFFVZEJNVlZGUTJoTldsSXlPWFphTW5oc1NVWlNlV1JZVGpCSlJrNXNZMjVhY0ZreVZucEpSWGhOVVhwRlZF' +
      'MUNSVWRCTVZWRlFYaE5TMUl4VWxSSlJVNUNTVVJHUlU1RVEwTkJVMGwzUkZGWlNrdHZXa2xvZG1OT1FWRkZRa0pS' +
      'UVVSblowVlFRVVJEUTBGUmIwTm5aMFZDUVV0MlFYRnhVRU5GTWpkc01IYzVla000WkZSUVNVVTRPV0pCSzNoVWJV' +
      'UmhSemQ1TjFabVVUUmpLMjFQVjJoc1ZXVmlWVkZ3U3pCNWRqSnlOamM0VWtwRmVFc3dTRmRFYW1WeEsyNU1TVWhP' +
      'TVVWdE5XbzJja0ZTV21sNGJYbFNVMnBvU1ZJd1MwOVJVRWRDVFZWc1pITmhlblJKU1VvM1R6Qm5Memd5Y1dvdmRr' +
      'ZEViQzh2TTNRMGRGUnhlR2xTYUV4UmJsUk1XRXBrWlVJck1rUm9hMlJWTmtsSlozZzJkMDQzUlRWT1kxVklNMUpq' +
      'YzJWcVkzRnFPSEExVTJveE9YWkNiVFpwTVVab2NVeEhlVzFvVFVaeWIxZFdWVWRQTTNoMFNVZzVNV1J6WjNrMFpV' +
      'WkxZMlpMVmt4WFN6TnZNakU1TUZFd1RHMHZVMmxMYlV4aVVrbzFRWFUwZVRGbGRVWktiVEpLVFRsbFFqZzBSbXR4' +
      'WVROcGRuSllWMVZsVm5SNVpUQkRVV1JMZG5OWk1rWnJZWHAyZUhSNGRuVnpURXA2VEZkWlNHczFOWHBqVWtGaFkw' +
      'UkJNbE5sUlhSQ1lsRm1SREZ4YzBOQmQwVkJRV0ZQUTBGWVdYZG5aMFo1VFVFMFIwRXhWV1JFZDBWQ0wzZFJSVUYz' +
      'U1VKb2FrRmtRbWRPVmtoVFZVVkdha0ZWUW1kbmNrSm5SVVpDVVdORVFWRlpTVXQzV1VKQ1VWVklRWGRKZDBWbldV' +
      'UldVakJVUVZGSUwwSkJaM2RDWjBWQ0wzZEpRa0ZFUVdSQ1owNVdTRkUwUlVablVWVktaVWxaUkhKS1dHdGFVWEUx' +
      'WkZKa2FIQkRSRE5zVDNwMVNrbDNTSGRaUkZaU01HcENRbWQzUm05QlZUVkxPSEpLYmtWaFN6Qm5ibWhUT1ZOYWFY' +
      'cDJPRWxyVkdOVU5IZGhRVmxKUzNkWlFrSlJWVWhCVVVWRldFUkNZVTFEV1VkRFEzTkhRVkZWUmtKNlFVSm9hSEJ2' +
      'WkVoU2QwOXBPSFppTWs1NlkwTTFkMkV5YTNWYU1qbDJXbms1Ym1SSVRubE5WRUYzUW1kbmNrSm5SVVpDVVdOM1FX' +
      'OVphMkZJVWpCalJHOTJURE5DY21GVE5XNWlNamx1VEROS2JHTkhPSFpaTWxaNVpFaE5kbG96VW5wamFrVjFXa2RX' +
      'ZVUxRVVVZEJNVlZrU0hkUmRFMURjM2RMWVVGdWIwTlhSMGt5YURCa1NFRTJUSGs1YW1OdGQzVmpSM1J3VEcxa2Rt' +
      'SXlZM1phTTFKNlkycEZkbG96VW5wamFrVjFXVE5LYzAxRk1FZEJNVlZrU1VGU1IwMUZVWGREUVZsSFdqUkZUVUZS' +
      'U1VKTlJHZEhRMmx6UjBGUlVVSXhibXREUWxGTmQwdHFRVzlDWjJkeVFtZEZSa0pSWTBOQlVsbGpZVWhTTUdOSVRU' +
      'Wk1lVGwzWVRKcmRWb3lPWFphZVRsNVdsaENkbU15YkRCaU0wbzFUSHBCVGtKbmEzRm9hMmxIT1hjd1FrRlJjMFpC' +
      'UVU5RFFXZEZRVWxXVkc5NU1qUnFkMWhWY2pCeVFWQmpPVEkwZG5WVFZtSkxVWFZaZHpOdVRHWnNUR1pNYURWQldW' +
      'ZEZaVlpzTDBSMU1UaFJRVmRWVFdSalNqWnZMM0ZHV21Kb1dHdENTREJRVG1OM09UZDBhR0ZtTWtKbGIwUlpXVGxE' +
      'YXk5aUsxVkhiSFZvZURBMmVtUTBSVUptTjBnNVVEZzBibTV5ZDNCU0t6UkhRa1JhU3l0WWFETkpNSFJ4U25reWNt' +
      'ZFBjVTVFWm14eU5VbE5VVGhhVkZkQk0zbHNkR0ZyZWxOQ1MxbzJXSEJHTUZCd2NYbERVblp3TDA1RFIzWXlTMWd5' +
      'VkhWUVEwcDJjMk53TVM5dE1uQldWSFI1UW1wWlVGSlJLMUYxUTFGSFFVcExhblJPTjFJMVJFWnlabFJ4VFZkMldX' +
      'ZFdiSEJEU2tKcmQyeDFOeXMzUzFrelkxUkpabnBGTjJOdFFVeHphMDFMVGt4MVJIb3JVbnBEWTNOWlZITldZVlUz' +
      'Vm5BemVFdzJNRTlaYUhGR2EzVkJUMDk0UkZvMmNFaFBhamtyVDBwdFdXZFFiVTlVTkZnekt6ZE1OVEZtV0VwNVVr' +
      'ZzVTMlpNVWxBMmJsUXpNVVExYm0xelIwRlBaMW95Tmk4NFZEbG9jMEpYTVhWdk9XcDFOV1phVEZwWVZsWlROVWd3' +
      'U0hsSlFrMUZTM2xIVFVsUWFFWlhjbXgwTDJoR1V6STRUakY2WVV0Sk1GcENSMFF6WjFsblJFeGlhVVJVT1daSFdI' +
      'TjBjR3NyUm0xak5HOXNWbXhYVUhwWVpUZ3hkbVJ2Ulc1R1luSTFUVEkzTWtoa1owcFhieXRYYUZRNVFsbE5NRXBw' +
      'SzNka1ZtMXVVbVptV0dkc2IwVnZiSFZVVG1OWGVtTTBNV1JHY0dkS2RUaG1Sak5NUnpCbmJESnBZbE5aYVVOcE9X' +
      'RTJhSFpWTUZSd2NHcEtlVWxYV0doclNsUmpUVXBzVUhKWGVERldlWFJGVlVkeVdESnNNRXBFZDFKcVZ5ODJOVFp5' +
      'TUV0V1FqQXllRWhTUzNadE1scExTVEF6Vkdkc1RFbHdiVlpEU3pOclFrdHJTMDV3UWs1clJuUTRjbWhoWm1ORFMw' +
      'OWlPVXA0THpsMGNFNUdiRkZVYkRkQ016bHlTbXhLVjJ0U01UZFJibHB4Vm5CMFJtVlFSazlTYjFwdFJucE5QU0lz' +
      'SWsxSlNVWlpha05EUWtWeFowRjNTVUpCWjBsUlpEY3dUbUpPY3pJclVuSnhTVkV2UlRoR2FsUkVWRUZPUW1kcmNX' +
      'aHJhVWM1ZHpCQ1FWRnpSa0ZFUWxoTlVYTjNRMUZaUkZaUlVVZEZkMHBEVWxSRldrMUNZMGRCTVZWRlEyaE5VVkl5' +
      'ZUhaWmJVWnpWVEpzYm1KcFFuVmthVEY2V1ZSRlVVMUJORWRCTVZWRlEzaE5TRlZ0T1haa1EwSkVVVlJGWWsxQ2Ew' +
      'ZEJNVlZGUVhoTlUxSXllSFpaYlVaelZUSnNibUpwUWxOaU1qa3dTVVZPUWsxQ05GaEVWRWwzVFVSWmVFOVVRWGRO' +
      'UkVFd1RXeHZXRVJVU1RSTlJFVjVUMFJCZDAxRVFUQk5iRzkzVW5wRlRFMUJhMGRCTVZWRlFtaE5RMVpXVFhoSmFr' +
      'Rm5RbWRPVmtKQmIxUkhWV1IyWWpKa2MxcFRRbFZqYmxaNlpFTkNWRnBZU2pKaFYwNXNZM2xDVFZSRlRYaEdSRUZU' +
      'UW1kT1ZrSkJUVlJETUdSVlZYbENVMkl5T1RCSlJrbDRUVWxKUTBscVFVNUNaMnR4YUd0cFJ6bDNNRUpCVVVWR1FV' +
      'RlBRMEZuT0VGTlNVbERRMmRMUTBGblJVRjBhRVZEYVhnM2FtOVlaV0pQT1hrdmJFUTJNMnhoWkVGUVMwZzVaM1pz' +
      'T1UxbllVTmpabUl5YWtndk56Wk9kVGhoYVRaWWJEWlBUVk12YTNJNWNrZzFlbTlSWkhObWJrWnNPVGQyZFdaTGFq' +
      'WmlkMU5wVmpadWNXeExjaXREVFc1NU5sTjRia2RRWWpFMWJDczRRWEJsTmpKcGJUbE5XbUZTZHpGT1JVUlFhbFJ5' +
      'UlZSdk9HZFpZa1YyY3k5QmJWRXpOVEZyUzFOVmFrSTJSekF3YWpCMVdVOUVVREJuYlVoMU9ERkpPRVV6UTNkdWNV' +
      'bHBjblUyZWpGcldqRnhLMUJ6UVdWM2JtcEllR2R6U0VFemVUWnRZbGQzV2tSeVdGbG1hVmxoVWxGTk9YTkliV3Rz' +
      'UTJsMFJETTRiVFZoWjBrdmNHSnZVRWRwVlZVck5rUlBiMmR5UmxwWlNuTjFRalpxUXpVeE1YQjZjbkF4V210cU5W' +
      'cFFZVXMwT1d3NFMwVnFPRU00VVUxQlRGaE1NekpvTjAweFlrdDNXVlZJSzBVMFJYcE9hM1JOWnpaVVR6aFZjRzEy' +
      'VFhKVmNITjVWWEYwUldvMVkzVklTMXBRWm0xbmFFTk9Oa296UTJsdmFqWlBSMkZMTDBkUU5VRm1iRFF2V0hSalpD' +
      'OXdNbWd2Y25Nek4wVlBaVnBXV0hSTU1HMDNPVmxDTUdWelYwTnlkVTlETjFoR2VGbHdWbkU1VDNNMmNFWk1TMk4z' +
      'V25CRVNXeFVhWEo0V2xWVVVVRnpObkY2YTIwd05uQTVPR2MzUWtGbEsyUkVjVFprYzI4ME9UbHBXVWcyVkV0WUx6' +
      'RlpOMFI2YTNabmRHUnBlbXByV0ZCa2MwUjBVVU4yT1ZWM0szZHdPVlUzUkdKSFMyOW5VR1ZOWVROTlpDdHdkbVY2' +
      'TjFjek5VVnBSWFZoS3l0MFoza3ZRa0pxUmtaR2VUTnNNMWRHY0U4NVMxZG5lamQ2Y0cwM1FXVkxTblE0VkRFeFpH' +
      'eGxRMlpsV0d0clZVRkxTVUZtTlhGdlNXSmhjSE5hVjNkd1ltdE9SbWhJWVhneWVFbFFSVVJuWm1jeFlYcFdXVGd3' +
      'V21OR2RXTjBURGRVYkV4dVRWRXZNR3hWVkdKcFUzY3hia2cyT1UxSE5ucFBNR0k1WmpaQ1VXUm5RVzFFTURaNVN6' +
      'VTJiVVJqV1VKYVZVTkJkMFZCUVdGUFEwRlVaM2RuWjBVd1RVRTBSMEV4VldSRWQwVkNMM2RSUlVGM1NVSm9ha0ZR' +
      'UW1kT1ZraFNUVUpCWmpoRlFsUkJSRUZSU0M5TlFqQkhRVEZWWkVSblVWZENRbFJyY25semJXTlNiM0pUUTJWR1RE' +
      'RktiVXhQTDNkcFVrNTRVR3BCWmtKblRsWklVMDFGUjBSQlYyZENVbWRsTWxsaFVsRXlXSGx2YkZGTU16QkZlbFJU' +
      'Ynk4dmVqbFRla0puUW1kbmNrSm5SVVpDVVdOQ1FWRlNWVTFHU1hkS1VWbEpTM2RaUWtKUlZVaE5RVWRIUjFkb01H' +
      'UklRVFpNZVRsMldUTk9kMHh1UW5KaFV6VnVZakk1Ymt3eVpIcGpha1YzUzFGWlNVdDNXVUpDVVZWSVRVRkxSMGhY' +
      'YURCa1NFRTJUSGs1ZDJFeWEzVmFNamwyV25rNWJtTXpTWGhNTW1SNlkycEZkVmt6U2pCTlJFbEhRVEZWWkVoM1VY' +
      'Sk5RMnQzU2paQmJHOURUMGRKVjJnd1pFaEJOa3g1T1dwamJYZDFZMGQwY0V4dFpIWmlNbU4yV2pOT2VVMVRPVzVq' +
      'TTBsNFRHMU9lV0pFUVRkQ1owNVdTRk5CUlU1RVFYbE5RV2RIUW0xbFFrUkJSVU5CVkVGSlFtZGFibWRSZDBKQlow' +
      'bDNSRkZaVEV0M1dVSkNRVWhYWlZGSlJrRjNTWGRFVVZsTVMzZFpRa0pCU0ZkbFVVbEdRWGROZDBSUldVcExiMXBK' +
      'YUhaalRrRlJSVXhDVVVGRVoyZEZRa0ZFVTJ0SWNrVnZiemxETUdSb1pXMU5XRzlvTm1SR1UxQnphbUprUWxwQ2FV' +
      'eG5PVTVTTTNRMVVDdFVORlo0Wm5FM2RuRm1UUzlpTlVFelVta3habmxLYlRsaWRtaGtSMkZLVVROaU1uUTJlVTFC' +
      'V1U0dmIyeFZZWHB6WVV3cmVYbEZiamxYY0hKTFFWTlBjMmhKUVhKQmIzbGFiQ3QwU21GdmVERXhPR1psYzNOdFdH' +
      'NHhhRWxXZHpReGIyVlJZVEYyTVhabk5FWjJOelI2VUd3MkwwRm9VM0ozT1ZVMWNFTmFSWFEwVjJrMGQxTjBlalpr' +
      'VkZvdlEweEJUbmc0VEZwb01VbzNVVXBXYWpKbWFFMTBabFJLY2psM05Ib3pNRm95TURsbVQxVXdhVTlOZVN0eFpI' +
      'VkNiWEIyZGxsMVVqZG9Xa3cyUkhWd2MzcG1ibmN3VTJ0bWRHaHpNVGhrUnpsYVMySTFPVlZvZG0xaFUwZGFVbFpp' +
      'VGxGd2MyY3pRbHBzZG1sa01HeEpTMDh5WkRGNGIzcGpiRTk2WjJwWVVGbHZka3BLU1hWc2RIcHJUWFV6TkhGUllq' +
      'bFRlaTk1YVd4eVlrTm5hamc5SWwxOS5leUp1YjI1alpTSTZJbTlWY0RrMlRUbE1ialpEWVN0alRGZzRaa3hqYTI1' +
      'bGFHMTVNMW8xTkZNNFEwOVVkbGc1Vm1zeEswazlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTJNamMyTkRnNE1UUTFO' +
      'amdzSW1Gd2ExQmhZMnRoWjJWT1lXMWxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBS' +
      'cFoyVnpkRk5vWVRJMU5pSTZJbFY0ZFRWcFVYa3lObEZoY1ZoU2IwcG1NMHcwY0ZSQksyNU1jbGxTWmxkMFlYSjRh' +
      'WEJSYzA1Q1pXczlJaXdpWTNSelVISnZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVS' +
      'cFoyVnpkRk5vWVRJMU5pSTZXeUk0VURGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpR' +
      'M1JoZVRGbk1qUk5QU0pkTENKaVlYTnBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpTd2laWFpoYkhWaGRHbHZibFI1Y0dV' +
      'aU9pSkNRVk5KUXl4SVFWSkVWMEZTUlY5Q1FVTkxSVVFpZlEuT0ZIY2NSTGlXOFB5VGhxeXJ5X0J4SzlBeDNqODNn' +
      'OVdFT2ZKdU5SeUctWnFfRVdtdkU2RS1sYWNFQWJlRzFNZV9Ib1JkS2tkMktYbWpkMU5lOWx4ampuRUZWZFJwaUt5' +
      'T1F0bFMyR2RnQnZRWEVoWEM1WDlBdDA0WGFyQkctVHlpOUNhX2lTLXRiNV9rcXNqYmFjVWRqSTN4RUI5YVdQTHF5' +
      'M3lPX3JFM1JFTDZIVlU5bE9XQWtfbE5qdkozU3dXQkthNVZwVDZOclZuMEp1UkFuZ2tYVmRjS1JlaVpKbFdaNW9j' +
      'V1l4ajgxY2ZYX2xPR29FM3ozZEtheG44U0ZNNTlVLTVUQm5Gdl9NTzBFRVUwVXJpSDhmQlp6UmdGSHFoUlNvRGs2' +
      'UmF1aUh0a0JjZjhRVkJ4TURwVXdFd25qOWc0OUVLSkFwVWtqcjZxcFpxdXRfcFBBaGF1dGhEYXRhWMVJlg3liA6M' +
      'aHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAAAuT_ZYfLmRi-xIoIAIkfeeABBAQsMmnEQ8OxpZxijXBMT4tya' +
      'mgkqC_3hr18_e8KeK8nG69ijcTaXNKX_CRmYiW0fegPE0N_3NVHEaj_kit7LPNOlAQIDJiABIVggxf5sshpkLLen' +
      '92NUd9sRVM1fVR6FRFZY_P7fnCq3crgiWCALN83GhRoAD4faTpk1bp7bGclHRleO922RvPUpSnBb-w',
    clientDataJSON:
      'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUhOWlE1WWFoZVpZOF9lYXdvM0VITHlXdjhCemlqaXFzQlVlNDZ2LVFTZyIsIm9yaWdpbiI6Imh0dHA6XC9cL2xvY2FsaG9zdDo0MjAwIiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiY29tLmFuZHJvaWQuY2hyb21lIn0',
  },
  type: 'public-key',
  clientExtensionResults: {},
  transports: [],
};
