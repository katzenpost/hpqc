package schemes

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHybridKEMOnly(t *testing.T) {
	// test using the KEM used in our PQ Noise protocol
	s := ByName("sntrup4591761-X25519")
	s2 := ByName("sntrup4591761-X25519-combiner")

	t.Logf("ciphertext size %d", s.CiphertextSize())
	t.Logf("shared key size %d", s.SharedKeySize())
	t.Logf("private key size %d", s.PrivateKeySize())
	t.Logf("public key size %d", s.PublicKeySize())
	t.Logf("seed size %d", s.SeedSize())
	t.Logf("encapsulation seed size %d", s.EncapsulationSeedSize())

	t.Logf("ciphertext size %d", s2.CiphertextSize())
	t.Logf("shared key size %d", s2.SharedKeySize())
	t.Logf("private key size %d", s2.PrivateKeySize())
	t.Logf("public key size %d", s2.PublicKeySize())
	t.Logf("seed size %d", s2.SeedSize())
	t.Logf("encapsulation seed size %d", s2.EncapsulationSeedSize())

	seed := make([]byte, s.SeedSize())
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	pubkey1, privkey1 := s.DeriveKeyPair(seed)
	pubkey2, privkey2 := s2.DeriveKeyPair(seed)

	pubkey1blob, err := pubkey1.MarshalBinary()
	require.NoError(t, err)
	pubkey2blob, err := pubkey2.MarshalBinary()
	require.NoError(t, err)

	require.True(t, hmac.Equal(pubkey1blob, pubkey2blob))

	encapseed := make([]byte, s.EncapsulationSeedSize())
	_, err = rand.Reader.Read(encapseed)
	require.NoError(t, err)

	ct1, ss1, err := s.EncapsulateDeterministically(pubkey1, encapseed)
	require.NoError(t, err)
	ct2, ss2, err := s2.EncapsulateDeterministically(pubkey2, encapseed)
	require.NoError(t, err)

	require.Equal(t, ct1, ct2)
	require.Equal(t, ss1, ss2)

	ss1b, err := s.Decapsulate(privkey1, ct1)
	require.NoError(t, err)

	ss2b, err := s2.Decapsulate(privkey2, ct2)
	require.NoError(t, err)

	require.Equal(t, ss1b, ss1)
	require.Equal(t, ss2b, ss1)

	require.Equal(t, ss1, ss1b)
}

func TestHybridKEMVectors(t *testing.T) {
	// test using the KEM used in our PQ Noise protocol
	s := ByName("Kyber768-X25519")

	/*
		pubkey1, privkey1, err := s.GenerateKeyPair()
		require.NoError(t, err)

		pubkey1bytes, err := pubkey1.MarshalBinary()
		require.NoError(t, err)
		privkey1bytes, err := privkey1.MarshalBinary()
		require.NoError(t, err)

		t.Logf("pubkey1 %x", pubkey1bytes)
		t.Logf("privkey1 %x", privkey1bytes)
	*/

	privkey1bytes, err := hex.DecodeString("f8053fb35e6715a6e0859924e8b318ab720d19b113c3fc7bb578d89120ea9a2ecb7500fa179841d3b1e8e0031bc8beefbabcee06c3d07b77d309b57a41a036d7763269b7b28a8ed62b1a01f3cff05a73e4c83cbf6291d6c45026d5648d9c7efc600ca6a05f4cc00e2e0508e9b2cc4ad3bd0ec1c819681e091a3df6b9b79afb6d85823997eab3e5e1b88c7cc9a53c544d6a6929631ea63734c54702eaa45ac0e60d09c673b23c3e1045b6b9188bae3985a2a80621479dda393a3580aabc16cf71b3c5df4042b19234b2d5975ba8c9b340cc2693840fd555867bcf0868371f96733d3b0167057b3a5c23bcba002da8730ed5a368a00ab772a81ba40406d65196615ad7cb30810793e2e1171977339c725105564fcf699ac39201c7109ef869244ae9b41062689a6ab493592da8a224ba191e4a084e41667676a3c00e7c1bb1000789bcc38697acbb36a8f9c104e60a5e88d02acdb148b24a095c0bc167469d5362ca82a1746f9c7b2a374fc0f7734d8862a3b7725c03918d46741ff1795db9475540c1eba16ea77289c0c8bd6d008b089698e5430c0559730cb0520ae227547b4ef939b6e76451ad4105b7cc9da78b5790ab68201b013df4b5c6a32ec1eb0c9af88b1fa76bc111077efa4a194867636343023769dc7bb2e46b58d54680aa968e95291efca3bca4e123bd21bc82bc2e65f2258ee14fbca234b041639ee59035ba088a1171bca629ab39a8dba2bdfb554318dab2fe39812455975c066d533538a895035ce325a3c858b4480204996338e67c0831c29a0c470d8c599af43ad9bcb4fbf4cdc3e9c1b19396200ba59ff61e409c8e552c4f086c84bdd1051f913a7ac70c70bc6fd320ac37f4cc6fb659304bb3a6ebcd3145276b676bfe644988553b78081f99d463971135de8cce1234006310b617d9a7984bcefe1c73f4686b9b34ae12561558d96fcb4b298cb64cfd60946fdc20fd4b62e484333207c7d84489aaab248297960a5314e27493b678391bea94ba00851e2551a4eab65bea7018c8568a8b4bf2f813f2d31d8991755625c00ff623785824c488c755c51948ac5227b52ad31c0a83799640290d7c373c756702986c4e5cd0c400553739c78ac764aca41b3cbe8365c561546df7be027188790494f1465460160fe0308197227ad39511d78314388cb3c01c790be37022873389d2c357d385fd23b55f530bf4d1251c51c650f834d3f80ed997668c994d4263b45629222a2430eaf75998da940a1377ea7286a7fb720d440074d103d3778dc86222f6114cad3c179e21a0ab43a2cfaab21c598cb0904634993bff8cc4a2bc91501a5481d3becb722a667519b8a477f3b5c7d7a6c45a4a7c87f7a984c53582a5454f464294e964bf6ba8af5994d034c8655416ee785ff817751cb0052cfbbd65e1130f743d6130a0140bc57ca23020814e7d71ad7092c51d4481ba4221fc19b14e14becbb830cce33a7751c4ebf316331c7fca66836048146076cf85695140401d8e8b785b385b34b021d5744a858553294b3b1315884c57ca9af2ae74baaf15f8267f2ccf4590c6b1f10989d448bdda21fa7766adc227ea38a3a72ca0da4c3018f45256920e910831bb280a2ac0a8bb0527b1a5a6819a0484112bbb60846b409f0368c24ad5089fc512f188c3dfba11bbf40b0b842339750ae07c829367010c4592020623ffb887b6333626ec32ebb4186f082a09001e27d451ab1bc2ae883d47963b82285d1240ccac2a442fd794bfd766f631b0b2f4a9ef5a38c997c78114c99e1758822a07b36b1eb66c2b59f42bc3d64c4168013e84c87fcc1abea173194443c5a9937b7aaf7728c39856964435a1bed83bc1293e750b1e72fa57371063b6046ab9d4a48054b43036306ea389bae07718668ad6e843e332a07e441d596601cdbb7ee5205b7712605ac9c6b9ea19c3a07a42115b3b865d7455360caaba3f59bf4b207ef3279d1d4b7c54a0554dd6465d262109a99e37fa1d7d5c2f4064a7c719bbcf795228f2c73f0571226c6c2143562da166d7b91e53d7901bdbb5753ab819a3933a027ce089998448220c8a0411e16c65f4030ac02614f9cf1d472621274a30ca1aaac6bcf9cca0f86c2fcab4162945569b469ee9faa0e1d91cc90c74c2b922b1c20025d00ed0453d63d47c6682c6fe0889c6b5802f91b1a1d175648c3aed938d5b5b491420a23a19152f8700362369af02896f9239f8c57b55795ac39848fe06c9e706a02452a0c1ab0aa2f94c290a6c4496390555b079d45807eb98b8859987f6706196808c014c77e40fefea9431d1be278b64d7519a9f5c0ce6045575349ba9f40188313d40189105590fa471a82333586f084616ecbcb8996994c7a81ac3bb4e705fba70a3a1f566e43867f5053315068633e5387ffacf0569722097349c6274e2e61b91870a7d9a39260bc14cc722f675ac5d5cc80e1bbd7078072237a37d10c2f765b789588c582701578caae474a6ba05023c419a2621c3114a0879307215540383b16521a547c32c34303578fe526adf31318855acfdf14f76d41f23daa6b4481db0c99ac0e7351ad0b74f090e16403702797ea1306503988420dc73cd562a37583128b5ab6e96b2bf291c0b190026d523fb166ff2d51dab510d7c6909eb15c177823b958b14f5127e3733ae1b3bbaa2a2694dda9164766937320fa680c00af0158ddcbce2b1566acb2207a4331e6564059ca6dd6a562753000d6c10721695eee1484a1379c36777e855926e898a338b7779212e221b20854028354b37ff9987568aae4a54ccd11a38f90b4e478b5a4c2828ece898a3020d32265dace0cdde149744c932ab7929ef0810d3fc07cb996efc2a3352d4684f44b51194490219841a96ab91524625889a19f6865762ab36fc4acb5bc74511b04e11831536c1b32685784b7bc3b3a8880b51d59207de375a39f66031307677f4988f5560cb87731058c600cb5b6cba3f5e432b2e898ca4890dbf37170e731a06e753b84785c16a9be7e4210e9417b6a4ab767308a723872de8b839b8552d659bee5b38c349a75f2b8d4dab64f9a1c35fd99e4be7a0c1d8caa7b314d84162accac62ef42408f81b6d218c45944ead23cf77679c18dc069e3375c89058011306cae1983fb33358b87546c9438ea4174223877067cd984ba34e839c93702798d9c9cc532d52416e58b815887a49c9654bc71cbd0cd31108458709560e37fa1cf41312c6371de753239da6151b4520b04a6296d17194a678de6ba76aac0ffe6366b52ba84082a2dee67304f8a33507cdd82437c6d38c4102475857ed7101177c84cdc57f707775e86751704dbc48b9ad5f990544ec5088b17c6ac4f72da85c84e3dfc02249915b179a384aa896dda606681259e68c832360a6bac7cb63b0a2584ccf70f5be7fe81d2c625dc8496536a23ff9def31983")
	require.NoError(t, err)
	pubkey1bytes, err := hex.DecodeString("8fb4b3512f9cd1030a9907e912bcde0e3865e825b9299952b17c7586e2c4500a0b842339750ae07c829367010c4592020623ffb887b6333626ec32ebb4186f082a09001e27d451ab1bc2ae883d47963b82285d1240ccac2a442fd794bfd766f631b0b2f4a9ef5a38c997c78114c99e1758822a07b36b1eb66c2b59f42bc3d64c4168013e84c87fcc1abea173194443c5a9937b7aaf7728c39856964435a1bed83bc1293e750b1e72fa57371063b6046ab9d4a48054b43036306ea389bae07718668ad6e843e332a07e441d596601cdbb7ee5205b7712605ac9c6b9ea19c3a07a42115b3b865d7455360caaba3f59bf4b207ef3279d1d4b7c54a0554dd6465d262109a99e37fa1d7d5c2f4064a7c719bbcf795228f2c73f0571226c6c2143562da166d7b91e53d7901bdbb5753ab819a3933a027ce089998448220c8a0411e16c65f4030ac02614f9cf1d472621274a30ca1aaac6bcf9cca0f86c2fcab4162945569b469ee9faa0e1d91cc90c74c2b922b1c20025d00ed0453d63d47c6682c6fe0889c6b5802f91b1a1d175648c3aed938d5b5b491420a23a19152f8700362369af02896f9239f8c57b55795ac39848fe06c9e706a02452a0c1ab0aa2f94c290a6c4496390555b079d45807eb98b8859987f6706196808c014c77e40fefea9431d1be278b64d7519a9f5c0ce6045575349ba9f40188313d40189105590fa471a82333586f084616ecbcb8996994c7a81ac3bb4e705fba70a3a1f566e43867f5053315068633e5387ffacf0569722097349c6274e2e61b91870a7d9a39260bc14cc722f675ac5d5cc80e1bbd7078072237a37d10c2f765b789588c582701578caae474a6ba05023c419a2621c3114a0879307215540383b16521a547c32c34303578fe526adf31318855acfdf14f76d41f23daa6b4481db0c99ac0e7351ad0b74f090e16403702797ea1306503988420dc73cd562a37583128b5ab6e96b2bf291c0b190026d523fb166ff2d51dab510d7c6909eb15c177823b958b14f5127e3733ae1b3bbaa2a2694dda9164766937320fa680c00af0158ddcbce2b1566acb2207a4331e6564059ca6dd6a562753000d6c10721695eee1484a1379c36777e855926e898a338b7779212e221b20854028354b37ff9987568aae4a54ccd11a38f90b4e478b5a4c2828ece898a3020d32265dace0cdde149744c932ab7929ef0810d3fc07cb996efc2a3352d4684f44b51194490219841a96ab91524625889a19f6865762ab36fc4acb5bc74511b04e11831536c1b32685784b7bc3b3a8880b51d59207de375a39f66031307677f4988f5560cb87731058c600cb5b6cba3f5e432b2e898ca4890dbf37170e731a06e753b84785c16a9be7e4210e9417b6a4ab767308a723872de8b839b8552d659bee5b38c349a75f2b8d4dab64f9a1c35fd99e4be7a0c1d8caa7b314d84162accac62ef42408f81b6d218c45944ead23cf77679c18dc069e3375c89058011306cae1983fb33358b87546c9438ea4174223877067cd984ba34e839c93702798d9c9cc532d52416e58b815887a49c9654bc71cbd0cd31108458709560e37fa1cf41312c6371de753239da6151b4520b04a6296d17194a678de6ba76aac0ffe6366b52ba84082a2dee67304f8a33507cdd82437c6d38c4102475857ed7101177c84cdc57f707775e86751704dbc48b9ad5f990544ec50")
	require.NoError(t, err)

	pubkey1, err := s.UnmarshalBinaryPublicKey(pubkey1bytes)
	require.NoError(t, err)

	privkey1, err := s.UnmarshalBinaryPrivateKey(privkey1bytes)
	require.NoError(t, err)

	//seed := make([]byte, s.EncapsulationSeedSize())
	//_, err = rand.Reader.Read(seed)
	//require.NoError(t, err)

	//t.Logf("seed %x", seed)

	seed, err := hex.DecodeString("085c73e9fbc3ed52e5a4a8139fe7365323be5aba8577412c119558002cc8eb9b14a090ec014f9bce9a116211bcfc7df4fa481b6d690ae1a52192fcf88261b715")
	require.NoError(t, err)

	ctA, ssA, err := s.EncapsulateDeterministically(pubkey1, seed)
	require.NoError(t, err)

	//t.Logf("KEM ciphertext: %x\n\n", ctA)
	//t.Logf("KEM shared secret: %x\n\n", ssA)

	ctB, err := hex.DecodeString("f0da7007ef34af862ec7e30e36b95ffa8b107dc4121dda55682ac1fe0182d1570a117541e9b6d84154b9f0a5a725ec2acbcae6df84560c2852777e9673ed8bb876dae689c4794e12d9ce9c643a661ddbd061961207e1c691a92e646abef8215e64b28e73550bfee4a036fc7152460386dde87eaef46e5d7377e790b5532ebc461e4ef05bee840a6e26a049e1b0912a429b2c51009e48823e2d6445869d3e1e11f19d3c9502249d006130bc20173b3f0e53c2e1d919e9adbd14412b7ed4c74b3a065db971414af5dbb2e5892706efecee95857f80471638205cb62df9d4d771124552526300dd609f5332632491a296d157d5edac34a1af2d50bd21d01441e141242b6b3b2b3dac947c3b4f9b2e7665ae3845647f794b71be3c3b9259022d614e1ab18eeca45f21ac1a4fa367f435f9268d91b749e4fb6a920025b73f96ec3cfcd5f2436f1e39855c4f2681df9543a27d621d9948a69febf4e6f1aab90f515e2c822ca957b561fc5f25a1977cb6d8f709262cadfede301b0e0be9e946c2840c69d3d90cec2d40c153d8f182968ddd114bda0b5dc9a876d2fb2270098539d4b06d6e472f039b1006c89ca12281918aab381f3ad540e47b6b308dabd2126281fa42149f3cf18c7921f044b8b02cef5ff929e7de6908bcce20cf8ca93a3532f42a2ac80ed3c33dfa081e64aefb332fac5d97acc192128a0e546ffb72ab35fdaab0f4f73ce21428b63dc16f5f12d933738a71874222b212d8de9545cba628f16d8611c09ad6705b72bcea36daa9d45a0ad48b46a640810163600017e48fd2be287b7b2f1f1c2388d6543eb23e3f93896287721c19f270897efd94fc465aff210348667e08e2b176e73ee6449d6b1d347ad31231ac3ddb9f980c1b832a4e201fa23bf468eaa534249c290bf995d1e5274dbedcea20bffef99ee1e1bf4de017c520565ad05dee64f5902543e56071bdae835e705afd50b6fc55bb512f8fed66f141a07f5bd1a7e33057af26d26239ed787368ecc5cd14ea94319f9015633fd50530a0a619ae1e4b460ae3a5c87032146ffac54e0ceb05562f100bcfefdb8aa3478446d8d4ef8c42c97cce1f4cfe87b28275b5c317543c3e6e9e7ec49452bae26d4e4505938a4fcedfe3495a7c53efa6e4332a5cf228830f3d3ff531626daf8f08629f4afd1c5592bd435cd62a0d38b28ae5516f21a7b51ca5ef80d284009d5cdbbc45c693669c1367a2b1ebfc0b2b9a7e3d96cda3f13a162392bd137e75c95ddefab10cd6d024a749d6b7012d822652ee720b114a8fd17561b25302e8ff50f7ab57d65a385aab6cd0f5dcc7c46ac092783d41d9edf86c4170b14367d2d5939009fa83398978e066e575c13908622f2cacd5128e46d22db1b505b02034b83231c514c8fe9f5494d8090a1544d0051c286c94e745c423a0f192a9ece63be72ad29e64460f9ae133bebd353e124b0a3577e26f9dbd6bdfd62d8456567ac7c831945d7064a9170c3712c4822f81a6b3851f1ac9e04592cc9b4d0ff863586e9ba4db6b560786668f607e2b5a4b349e14cf65d19a673d04bfe2849ef318440f35a9a86a33eca7")
	require.NoError(t, err)

	ssB, err := hex.DecodeString("76b5c514a42ff4d121518983cfe00d43a838876eb6b5bb867539a798cd4941af")
	require.NoError(t, err)

	require.Equal(t, ctA, ctB)
	require.Equal(t, ssA, ssB)

	ss1b, err := s.Decapsulate(privkey1, ctA)
	require.NoError(t, err)
	require.Equal(t, ssA, ss1b)
}