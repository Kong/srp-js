export async function decodeBase64(base64: string): Promise<Uint8Array> {
  let uri = 'data:application/octet-binary;base64,';
  uri += base64;

  const res = await fetch(uri);
  const buffer = await res.arrayBuffer();

  return new Uint8Array(buffer);
}

export async function encodeBase64(data: Uint8Array): Promise<string> {
  const dataUri = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        resolve(reader.result);
      } else {
        reject();
      }
    }
    reader.onerror = reject;
    reader.readAsDataURL(new Blob([data]));
  });

  const dataAt = dataUri.indexOf(',');
  if (dataAt === -1) {
    throw new Error(`unexpected data uri output: ${dataUri}`);
  }

  return dataUri.slice(dataAt + 1);
}
