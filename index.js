document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('file-input');
    const metadataDisplay = document.getElementById('metadata-display');
    const updateMetadataButton = document.getElementById('update-metadata');

    let pngBuffer;

    fileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (!file) {
            return;
        }

        const reader = new FileReader();
        reader.onload = (event) => {
            pngBuffer = event.target.result;
            const exifData = ExifReader.load(pngBuffer, { expanded: true });
            displayMetadata(exifData);
            updateMetadataButton.disabled = false;
        };
        reader.readAsArrayBuffer(file);
    });

    updateMetadataButton.addEventListener('click', () => {
        if (!pngBuffer) {
            return;
        }

        const newKey = '!PWNED!';
        const updatedBuffer = updateRev3alIdKey(pngBuffer, newKey);
        const newFile = new File([updatedBuffer], 'modified-image.png', { type: 'image/png' });
        saveAs(newFile);
    });

    function displayMetadata(metadata) {
        metadataDisplay.textContent = JSON.stringify(metadata, null, 2);
    }

    function updateRev3alIdKey(buffer, newKey) {
        const keyword = 'Rev3alIdKey';
        const textChunkHeader = 'tEXt';
        const chunkHeaderSize = 4;
        const chunkSizeSize = 4;
        const chunkCRCSize = 4;
        const keywordTerminatorSize = 1;
    
        const dataView = new DataView(buffer);
        const newKeyBuffer = new TextEncoder().encode(newKey);
        const newChunkSize = chunkHeaderSize + keyword.length + keywordTerminatorSize + newKeyBuffer.length + chunkCRCSize;
    
        let position = 8;
        const blobParts = [new Uint8Array(buffer, 0, position)];
        let newPosition = 8;
    
        const iendChunkHeader = 'IEND';
        let iendPosition = -1;
    
        while (position < buffer.byteLength) {
            const chunkSize = dataView.getUint32(position);
            const chunkType = String.fromCharCode(...new Uint8Array(buffer, position + chunkSizeSize, chunkHeaderSize));
    
            if (chunkType === iendChunkHeader) {
                iendPosition = position;
                break;
            }
    
            blobParts.push(new Uint8Array(buffer, position, chunkSize + chunkSizeSize + chunkHeaderSize + chunkCRCSize));
            newPosition += chunkSize + chunkSizeSize + chunkHeaderSize + chunkCRCSize;
            position += chunkSize + chunkSizeSize + chunkHeaderSize + chunkCRCSize;
        }
    
        if (iendPosition === -1) {
            throw new Error("IEND chunk not found");
        }
    
        const newChunkBuffer = new ArrayBuffer(newChunkSize);
        const newChunkDataView = new DataView(newChunkBuffer);
        newChunkDataView.setUint32(0, newKeyBuffer.length + keyword.length + keywordTerminatorSize);
        const newChunkArray = new Uint8Array(newChunkBuffer);
        newChunkArray.set(new TextEncoder().encode(textChunkHeader), chunkSizeSize);
        newChunkArray.set(new TextEncoder().encode(keyword), chunkSizeSize + chunkHeaderSize);
        newChunkArray[chunkSizeSize + chunkHeaderSize + keyword.length] = 0;
        newChunkArray.set(newKeyBuffer, chunkSizeSize + chunkHeaderSize + keyword.length + keywordTerminatorSize);

        const crc = crc32(new Uint8Array(newChunkBuffer, chunkSizeSize, newKeyBuffer.length + keyword.length + keywordTerminatorSize + chunkHeaderSize));
        newChunkDataView.setUint32(newChunkSize - chunkCRCSize, crc);
    
        blobParts.push(newChunkArray);
    
        blobParts.push(new Uint8Array(buffer, iendPosition, chunkSizeSize + chunkHeaderSize + chunkCRCSize));
    
        return new Blob(blobParts, { type: 'image/png' });
    }
    

    function makeCRCTable() {
        let c;
        let crcTable = [];
        for (let n = 0; n < 256; n++) {
            c = n;
            for (let k = 0; k < 8; k++) {
                c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
            }
            crcTable[n] = c;
        }
        return crcTable;
    }
    
    function crc32(buf) {
        let crcTable = window.crcTable || (window.crcTable = makeCRCTable());
        let crc = 0 ^ (-1);
    
        for (let i = 0; i < buf.length; i++) {
            crc = (crc >>> 8) ^ crcTable[(crc ^ buf[i]) & 0xFF];
        }
    
        return (crc ^ (-1)) >>> 0;
    }
    

    function saveAs(file) {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(file);
        a.download = file.name;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        URL.revokeObjectURL(a.href);
        document.body.removeChild(a);
    }
});

