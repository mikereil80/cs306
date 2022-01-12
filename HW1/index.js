// Michael Reilly
// I pledge my honor that I have abided by the Stevens Honor System.

const bitwiseXOR = require('bitwise-xor');

const ciphertexts = [
    `2d0a0612061b0944000d161f0c1746430c0f0952181b004c1311080b4e07494852`,
    `200a054626550d051a48170e041d011a001b470204061309020005164e15484f44`,
    `3818101500180b441b06004b11104c064f1e0616411d064c161b1b04071d460101`,
    `200e0c4618104e071506450604124443091b09520e125522081f061c4e1d4e5601`,
    `304f1d091f104e0a1b48161f101d440d1b4e04130f5407090010491b061a520101`,
    `2d0714124f020111180c450900595016061a02520419170d1306081c1d1a4f4601`,
    `351a160d061917443b3c354b0c0a01130a1c01170200191541070c0c1b01440101`,
    `3d0611081b55200d1f07164b161858431b0602000454020d1254084f0d12554249`,
    `340e0c040a550c1100482c4b0110450d1b4e1713185414181511071b071c4f0101`,
    `2e0a5515071a1b081048170e04154d1a4f020e0115111b4c151b492107184e5201`,
    `370e1d4618104e05060d450f0a104f044f080e1c04540205151c061a1a5349484c`
];

function hex2byte(string){
    // Converts the hexadecimal strings to byte arrays.
    return Buffer.from(string, 'hex');
}

function xor(str1, str2){
    // bitwise XOR 2 strings, and converts to ASCII to make it readable
    return bitwiseXOR(str1, str2).toString("ascii");
}

// Gonna look for spaces as stated in the assignment as a good idea
const spaces={};
ciphertexts.forEach(cipher=>{
    // Dummy values to replace when spaces are found
    spaces[cipher]=(new Array(33)).fill(0, 0, 33)
})

const knownKeyIndices=[];
// Dummy valoes for when the known parts of the key are found
const knownKey=(new Array(33)).fill(null, 0, 33);

ciphertexts.forEach(cipher=>{
    const cipherconverted=hex2byte(cipher);
    ciphertexts.forEach(ctext=>{
        const c_converted=hex2byte(ctext);
        if(cipher!==ctext){
            // XOR the two ciphertexts and then see whether an actual character is printed out.
            const XOR=xor(cipherconverted,c_converted);
            for(let i=0; i<XOR.length; i++){
                const character=XOR[i];
                // Checks if the character is within our possible character table
                if((/[a-zA-Z !?.,;:]/).test(character)){
                    spaces[cipher][i]=spaces[cipher][i]+1;
                }
            }
        }
    })

    const knownSpaces7=[];
    const currentSpaceIndex=spaces[cipher];
    for(let j=0; j<currentSpaceIndex.length; j++){
        // Basically kept testing this, and got the best key through brute force testing which value was best, landed on 7
        if(currentSpaceIndex[j]>=7){
            // Gives ?esting ?est?ng can you read t?i>
            knownSpaces7.push(j);
        }
    }

    // Hex value of a space is '20'
    const spacebyte=hex2byte('20'.repeat(33));
    const spaceXOR=xor(cipherconverted, spacebyte);
    // Leaving it as 7 since it is the most accurate
    // Test against spaces as the messages likely do have them, and are likely one of the most common characters in the plaintext.
    knownSpaces7.forEach(space=>{
        knownKey[space]=parseInt(spaceXOR[space].charCodeAt(0)).toString(16);
        knownKeyIndices.push(space);
    });
});

// If the value was never found for the key, make it null ('00' in hex), and then join it all together to a key
const messageKey=knownKey.map(x=>x||'00').join('');
console.log(messageKey);
const messageKeyByte=hex2byte(messageKey);
const textbyte=hex2byte(ciphertexts[0])
const messagebyte=xor(messageKeyByte, textbyte);
const result=[];
for(let k=0; k<messagebyte.length; k++){
    // In the message, for any non-known value put a '?' but otherwise use the correct character
    result[k]=knownKeyIndices.includes(k) ? messagebyte[k] : '?';
}
console.log(result.join(''));

// Guess the first message as "testing testing can you read this' based on the result
const message="testing testing can you read this";
function ascii_to_hex(str){
    let result=[];
    for(let l=0; l<str.length; l++){
        let hex=Number(str.charCodeAt(l)).toString(16);
        result.push(hex);
    }
    return result.join('');
}

// Can find key by XORing the message's hex with ciphertext
const messagehex=ascii_to_hex(message);
const messagehexbyte=hex2byte(messagehex);
const cipher0byte=hex2byte(ciphertexts[0]);

const key = xor(messagehexbyte, cipher0byte);
// Gives the key in ascii
console.log(key);
const keyhex=ascii_to_hex(key);
// Gives the key in hex
console.log(keyhex);

// The  XOR every ciphertext with the key to get the messages
ciphertexts.forEach(ciphertext => {
    const ciphertextbyte=hex2byte(ciphertext);
    const keybyte=hex2byte(keyhex);
    console.log(xor(ciphertextbyte, keybyte))
})

// Generate the new keys using the method given.
const concatArray=["00100001"]
function bit_to_ascii(array){
    let result="";
    for(let n=0; n<array.length; n++){
        result=String.fromCharCode(parseInt(array[n], 2));
    }
    return result;
}
// Will just concatenate the same character to the existing key
const newchar=bit_to_ascii(concatArray);
console.log(newchar)

let newkey=key;
for(let c=0; c<27; c++){
    newkey=newkey+newchar;
}
console.log(newkey);