<?php

namespace Esia\Signer;

use Esia\Signer\Exceptions\CannotReadCertificateException;
use Esia\Signer\Exceptions\CannotReadPrivateKeyException;

class SignerCPDataHash extends AbstractSignerPKCS7 implements SignerInterface
{
    public function sign(string $message): string
    {
        $store = new \CPStore();
        $store->Open(CURRENT_USER_STORE, 'My', STORE_OPEN_READ_ONLY); // используем хранилище My текущего пользователя (www-data)
        $certs = $store->get_Certificates();
        $certlist = $certs->Find(CERTIFICATE_FIND_SUBJECT_NAME, $this->config->getClientId(), 0); // ищем сертификат, у которогое Subject = мнемонике нашей ИС
        $cert = $certlist->Item(1);
        if (!$cert) {
            throw new CannotReadCertificateException('Cannot read the certificate');
        }        
        // у сертификата должна быть связка с закрытым ключом
        if (false===$cert->HasPrivateKey()) {
            throw new CannotReadPrivateKeyException('Cannot read the private key');
        }        

        $pk=$cert->PublicKey();
        $oid=$pk->get_Algorithm();                  
        $hd = new \CPHashedData();    
        switch ($oid->get_Value()) { // https://cpdn.cryptopro.ru/content/csp40/html/group___pro_c_s_p_ex_DP8.html
            case '1.2.643.7.1.1.1.1':
                $hd->set_Algorithm(CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256);
                break;
            case '1.2.643.7.1.1.1.2':
                $hd->set_Algorithm(CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512);
                break;
        }
        $hd->set_DataEncoding(BASE64_TO_BINARY);
        $hd->Hash($cert->Export(ENCODE_BASE64));      
        $this->clientCertHash=$hd->get_Value(); //получили ГОСТ хэш нашего сертификата
        unset($hd);

        $hd = new \CPHashedData();        
        $hd->set_Algorithm(CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256);
        $hd->set_DataEncoding(BASE64_TO_BINARY);
        $hd->Hash(base64_encode($message)); // посчитали ГОСТ хэш для $message
        $rs = new \CPRawSignature();
        $shash=$rs->SignHash($hd, $cert); // https://docs.cryptopro.ru/cades/reference/cadescom/cadescom_interface/irawsignaturesignhash :  Подпись для ключей ГОСТ Р 34.10-2001 возвращается как описано в разделе 2.2.2 RFC 4491 (http://tools.ietf.org/html/rfc4491#section-2.2.2), но в обратном порядке байт.
        $signed=base64_encode(strrev(hex2bin($shash))); // получили подписанный data hash

        $sign = str_replace("\n", '', $this->urlSafe($signed));
        return $sign;
    }
}
