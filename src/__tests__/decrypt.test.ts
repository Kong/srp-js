import { Client, computeVerifier, genKey, params as _params, Server } from "..";
import { Buffer } from "node:buffer";
import { describe, beforeAll, beforeEach, it, assert } from "vitest";
import { decryptAES, decryptRSAWithJWK, deriveKey } from "../crypt";

describe("decryption", () => {
    it("should decrypt encryptedProjectSymmetricKey", async () => {
        const browserEncryptedKeys = {
            EncPrivateKey:   `{"iv":"7e545ceeb4a2c1baf71334b5","t":"d6377da72d8ab3cf8a7e904adcc9b472","d":"5fe8514cea0401eca94cb74be724789203eecac3cd70f6d4e85ae04e2364d3638ac67e05aeef9a79177207d8110b178acc39c8fde25b929e6e60984cad562d34c674a6501694ecdefbe118020e8d391a30fc3d5c479d7a8781bc5607e57d938075bd641acdda215dc6078b7600ce7ff5b2d8974247bb4a2c5abc22692d2d74e5d02b552201b8d8b21290adc95b0db963f99d82dd12ecacd96ae57372d2abbaf4c66e537affe031713194ac3af95f41906687cfc0b3687b7b1f1e4fd62976cfecc8163f83a45b71959836eb802189f60500ba677900e81839ce2f7c3968eaf3711c00a56c3fe17a203d713a1163da1a1977306733b4140cda3ad503002dce7056a175f7e522e4ca99996468c9aefa27408a4df534a0991c210c34213abed9d9f277e845cb65bbfb57c086948cf697a6387bf438cc950798ff282b99c728085fa037c4a5117ea5fba7ddbeb5878a60fa695f480a12094f11d9a7c1f8876e0b1d60c22036420346331c1879c51764af4ee6879c7b4c43e6e65355bb66556411a70b2a1b901c80ff8d01b0d44a4db71e5ae5fb3c31e8aa8a2e2ab8872ee7beddc19a1c27456e5eb50719ba666681d0d336d14111efeeaa5133a27abf0f7e67c58f84535605875a10e8200eb930b1629312eb0ef5f2183475ce275802dea0336f1f9ff6ccbc89752a3e6ff5cdb22b832110ed530957e08663cfde4667a2e9cc913020560e9d273d084654b7741fd6078264022128563a3d3ab2eb61065f72217ac9954fdff3725b5fe3dbb14415d2327b78f2b5b2eaf1a6d1abc7c908dc8131df4cc2e35adad77607cd742f056b2e086b11d79f9f23f33c50481e994274ebe3206f1fee30488d0d452adaff0fd033bba8fcb357d1df192a3b15c9a665a61ca9c4fb8984e8e01230aa8c9a7dc918cde7eec70f912a094ccd04006dedb4314427a87f2df1854478ce530360545e15ab2794828b07bf07ba9a63e5a65d95a8ac377030664a2eef02a98257d5d3436c1243a04488581b8b198d9c03e70eaffb83e9137d4082ffd7ee29e87389003566a90fe821331660b08731d4a5cfd119e028391ac431ff0d8eab6878be47e75f1631bca2c19e4a7838da263ff58a810f7bcefa8ef9d5285b47b04514c5a080978bc1d43fd610769f8c2c5fe1519bd0c69bee298d6fde5529cc4025358ebbe29518b063f65dddf4d2694bf08ec0e486b802649a0f8c6f13eef6463fb08538a76ffc90174315133ac04e64d931f128d6c40f47f454800cd25ea44687f93101653da03e09a464127cab206a19c5eff0e474737c152a0d769686cf390f2f848af13e21c1d8bcc0282d0909e3a596d4108e2f2deee821338fee1c474dbd0aca217266931754a01102dd5b44c204dbe09e748310174b0ddfcc42db552079ea7293e9071a99cdd33d3f83f6249895595ee911d5273a81412ceacb691659e37d1ed7a840322801920aa71b6879b92937d93f197606e2a65f2d96ab9ad34e376ae7734dcf6f4c5a7f4bc3e541ee97f2d444662b3a3f85e7e68343b1d34d9ff9e8f43f695aec7df2fae4f36d92b0d0bb293753bf77c852517dee16246841191d313f84227629d35bd4516c5b3f9b3c8830cce3e05bb7d039e98998572fec93d43a14fbfdbed0ec03201c7be62e2180e05fde56a24a3b858fccc5557bad711e5d47b51f56a86e0bf29a7e3a1385936adde90fe9f7d1163ded90e0e5e99307ba9de1193b2e78a77383b2566025f10de6541b89cfdb50cb6cc8d217d383beb49640aa0aebbaf8c0874fe74a73fe8f4e66f23702b1294c87eafa4941aff047792baad0786bca2cf97973039831151a0b8e26e30202235aa43c36cfb2e43fea2cebb6b8476e1745aa8e39a9069e502407415901a0e2bfa56b07c813d139f0701ed0669ed1495ce61629252a55f63d65880fdbf3360e145343d8ebfe6e8b79535f72c498246b7dc736f36c409c49149aef54de31bcf51b59a4d4bfaade5f69737997a154fc493e4881a4398a63f3c73ad9c6433095e817c52669d48fa62e2525f954721ca0609b02799e59c0e8fa768401dd0717960c8f189393db7d1c61777737211245327d36fe10001881241a6acaafcf7e22dbb22ebacf44f2ea2abc0430d43f324f8f379bbc489d96684a8c906cb9568b5e057b40b4be73f3382740a83662f39d2a868e0771770dbdb630979a740950b9be0506cfdf48ed787035177d0e89fd8de1ce64acee838eb5f6484cabe81878ae0fc3ac9106f1c4507ceb772c255811080b860e487de71e2716e51963f9bc0f1532935875a5181607cbe58e74ccf72d5e3c360cf0ee0deeb62801567610157f217f74f00cbaf2c9403cda5f4bf54049e73afa81e415f988e0e4704501ef91c04496afbe9409e3edece49ad71cfb2f646d13c37a2ce0c7201eaf2d9b57a7ad4adc185fc278b374400698751e8ba983281b1e275f7d7075b052af3705b1fa88b7aa7cb53eb708470376dc54d2e0233b6e990e6f3931420afab4191159122a22df0b649683bc8a112b26e4ec3ff01897ca4aba7a3548805e48486e003e8c8d136d8e7fcd","ad":""}`,
            EncSymmetricKey: `{"iv":"e8b9e56cce562e71d18a239c","t":"9275a8bbd6c72d0bb93ca280140fbde0","d":"bbe54a02989e95316cee850bcf033a63da5bdadc05af54e9ea17e90de433310d23298e42743041d2402f125320ed42c1f378bfeadecc9aa0fa80d2f1e28757ce3a09645c1bdc09e7b55af03464d9e08fa548edca747ca5fbd6f4f3852ff63de6388e48361635cd72f44a3dea7592b80804e48b876b1b9a8ba143515c469def8796ea8d51c964fa59caea199daaac4a15fe1596978ec97ee2a4d993f68a4b39c607511fcbee741ed6beb9dab1585dc447be236cac4fd250be3e7150cbf6d3","ad":""}`,
            PublicKey:       `{"alg":"RSA-OAEP-256","e":"AQAB","ext":true,"key_ops":["encrypt"],"kty":"RSA","n":"p7g-_rRvNzZ0jfU8M6B7WhhK_SOVigBUDYa8ccRXFdJy80jBSyT4WEESq_14A-dYG20XXih1kY-0iKB_gxjcomhe3iVRIH95uPuBeZ8Vb5pJtcPO-II_3wWk7qypbISn6CuKFueeN-7aNlLY5qvIaUVDELIpYX3hPp5WJ4_oBxAWRlm3YkeKEgiKhRNKdDay7mwpq7sUu3hfUVWi6JfidKs_r6yKSBIEhSIB7gB3EFDUQBBcqHQDT1_Q2WAEdLRjqyZmQNyDZCvbJQlaq_NWlDpp110YKL7L7qrdlj1XpFigRnrKSG7dtM83mLvVBQepG5kqv1PeIwnxIXBJfzUJ7w"}`,
            SaltAuth:        "2b9799588318b56ce8b96f37399c6972edf2b8b474b26df665ae55222ecfed2c",
            SaltEnc:         "cf42b5345333c160c22d77a23178f73b381ef1dbeef2ccb1621bcd3f696cd1cf",
            SaltKey:         "3b4885da0f6952f0cef3ee4338cfddff950985090ba79a51b0fc6008876d41d3",
        }

        const secret = await deriveKey("Insomnia@123", "kimmarker613@gmail.com", browserEncryptedKeys.SaltEnc);
        assert.equal(secret, "4ffcd69101567aaa8c2132b879b2ebe126f4840ec83b8f353980912c2fcccb0a");

        const symmetricKey = decryptAES(secret, JSON.parse(browserEncryptedKeys.EncSymmetricKey))
        const privateKeyJWK = decryptAES(JSON.parse(symmetricKey), JSON.parse(browserEncryptedKeys.EncPrivateKey));

        const decrypted = decryptRSAWithJWK(JSON.parse(privateKeyJWK), "8204ee2ccc57fde3ef65f86bc2e7fd09e366b7bffe08627db63508cf86b4dc0a96d2d247053d0d8e79a7d4f5d97d6fd208aa265eea2d502b6c3808238c9c526899a043230d1c2d942e79b186067ecf347d126f50ac4f4cca0247dcb12b58ff675c0af97525eb8e027e1a33cd1e133664e8176983a63a52e7df19aca06bf9b73f3b5e6c13700565977dce0e9b8a5958105e459318d899d5b8f06ef55e562f52d47883ec63a7621a97c9d3ede1e6b479d0a56712ff87b9988c51aff4ff077d38a5dc40b27e8abad2ae59776c518044ac6fac19da6d15501e215d232c7b73442fd4efefdbbbcaaf5362f5b5905fd391a470862019ef59dca4e07675992914ea6a9b");
        assert.equal(decrypted, "8b52e943810c3a676335df6ce1961415b7894a2b5b3c45a74f521037644ad983");
    });
});
