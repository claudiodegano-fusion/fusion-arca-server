// Fusion CRM — Servidor ARCA para Render.com (archivo único)
'use strict';

const express  = require('express');
const cors     = require('cors');
const forge    = require('node-forge');
const axios    = require('axios');
const xml2js   = require('xml2js');
const moment   = require('moment-timezone');

// ═══════════════════════════════════════════════════
// WSAA — Autenticación y Autorización
// ═══════════════════════════════════════════════════
// arca/wsaa.js — Web Service de Autenticación y Autorización (WSAA)

const WSAA_URL = 'https://wsaa.afip.gov.ar/ws/services/LoginCms';

/**
 * Genera el TRA (Ticket de Requerimiento de Acceso)
 */
function generarTRA(servicio = 'wsfe') {
  const now = moment().tz('America/Argentina/Buenos_Aires');
  const genTime = now.clone().subtract(10, 'minutes').format('YYYY-MM-DDTHH:mm:ss-03:00');
  const expTime = now.clone().add(12, 'hours').format('YYYY-MM-DDTHH:mm:ss-03:00');
  const uid = Math.floor(Date.now() / 1000);

  return `<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>${uid}</uniqueId>
    <generationTime>${genTime}</generationTime>
    <expirationTime>${expTime}</expirationTime>
  </header>
  <service>${servicio}</service>
</loginTicketRequest>`;
}

/**
 * Firma el TRA con PKCS7 usando la clave privada y el certificado
 */
function firmarTRA(traXml, certPem, keyPem) {
  const cert = forge.pki.certificateFromPem(certPem);
  const key  = forge.pki.privateKeyFromPem(keyPem);

  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(traXml, 'utf8');
  p7.addCertificate(cert);
  p7.addSigner({
    key,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.signingTime, value: new Date() },
      { type: forge.pki.oids.messageDigest },
    ],
  });
  p7.sign({ detached: false });

  const der  = forge.asn1.toDer(p7.toAsn1()).getBytes();
  const b64  = forge.util.encode64(der);
  return b64;
}

/**
 * Llama al WSAA y devuelve { token, sign, expiracion }
 */
async function loginWSAA(certPem, keyPem) {
  const tra    = generarTRA('wsfe');
  const cmsFirmado = firmarTRA(tra, certPem, keyPem);

  const soapBody = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope
  xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:wsaa="http://wsaa.view.sua.dvadac.desein.afip.gov">
  <soapenv:Header/>
  <soapenv:Body>
    <wsaa:loginCms>
      <wsaa:in0>${cmsFirmado}</wsaa:in0>
    </wsaa:loginCms>
  </soapenv:Body>
</soapenv:Envelope>`;

  const resp = await axios.post(WSAA_URL, soapBody, {
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
      SOAPAction: '""',
    },
    timeout: 30000,
  });

  const parsed = await xml2js.parseStringPromise(resp.data, { explicitArray: false });
  const loginReturn =
    parsed['soapenv:Envelope']['soapenv:Body']['loginCmsReturn'] ||
    parsed['soapenv:Envelope']['soapenv:Body']['ns1:loginCmsReturn'] ||
    parsed['S:Envelope']['S:Body']['ns2:loginCmsResponse']['return'];

  const inner = await xml2js.parseStringPromise(loginReturn, { explicitArray: false });
  const credentials = inner['loginTicketResponse']['credentials'];
  const header = inner['loginTicketResponse']['header'];

  return {
    token: credentials['token'],
    sign:  credentials['sign'],
    expiracion: header['expirationTime'],
  };
}




// ═══════════════════════════════════════════════════
// WSFEv1 — Facturación Electrónica
// ═══════════════════════════════════════════════════
// arca/wsfev1.js — Web Service de Facturación Electrónica v1 (WSFEv1)

const WSFEV1_URL = 'https://servicios1.afip.gov.ar/wsfev1/service.asmx';
const NS = 'http://ar.gov.afip.dif.FEV1/';

// Tipos de comprobante
const TIPOS_CBTE = {
  'A': 1,   // Factura A
  'B': 6,   // Factura B
  'C': 11,  // Factura C
  'M': 51,  // Factura M
  'E': 19,  // Factura E (Exportación)
};

// Alícuotas IVA
const ALICUOTAS = {
  '0':    3,   // 0%
  'ex':   2,   // Exento
  '10.5': 4,   // 10.5%
  '21':   5,   // 21%
  '27':   6,   // 27%
};

// Condición IVA del receptor para cada tipo de comprobante
const DOC_TIPO_CF = 99;   // Consumidor Final
const DOC_NRO_CF  = 0;

/**
 * Formatea fecha YYYYMMDD para ARCA
 */
function fmtFecha(date) {
  return moment(date).tz('America/Argentina/Buenos_Aires').format('YYYYMMDD');
}

/**
 * Construye el XML SOAP para FECompUltimoAutorizado
 * Devuelve el último número de comprobante autorizado para un PV y tipo
 */
async function ultimoNumero({ token, sign, cuit }, ptoVta, cbteTipo) {
  const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="${NS}">
  <soap:Body>
    <ar:FECompUltimoAutorizado>
      <ar:Auth>
        <ar:Token>${token}</ar:Token>
        <ar:Sign>${sign}</ar:Sign>
        <ar:Cuit>${cuit}</ar:Cuit>
      </ar:Auth>
      <ar:PtoVta>${ptoVta}</ar:PtoVta>
      <ar:CbteTipo>${cbteTipo}</ar:CbteTipo>
    </ar:FECompUltimoAutorizado>
  </soap:Body>
</soap:Envelope>`;

  const resp = await axios.post(WSFEV1_URL, soap, {
    headers: { 'Content-Type': 'text/xml; charset=utf-8', SOAPAction: `"${NS}FECompUltimoAutorizado"` },
    timeout: 30000,
  });

  const parsed = await xml2js.parseStringPromise(resp.data, { explicitArray: false });
  const body   = Object.values(Object.values(parsed)[0])[0];
  const result = body['FECompUltimoAutorizadoResult'] || body['m:FECompUltimoAutorizadoResult'];
  const cbteNro = parseInt(result['CbteNro'] || result['m:CbteNro'] || '0');
  return cbteNro;
}

/**
 * Construye el detalle XML de un comprobante
 */
function buildDetalle(item, nroDesde, nroHasta, today) {
  const tipoCbte = TIPOS_CBTE[item.tipoCbte] || 6;
  const esCF     = item.tipoCbte === 'B' || item.tipoCbte === 'C';
  const docTipo  = esCF ? DOC_TIPO_CF : 80;
  const docNro   = esCF ? DOC_NRO_CF  : (item.cuit || '').replace(/\D/g, '') || 0;

  const alicKey  = String(item.alicuotaIva || '21');
  const alicId   = ALICUOTAS[alicKey] || 5;
  const impTotal = parseFloat(item.importeTotal || 0).toFixed(2);
  const impNeto  = item.tipoCbte === 'A' || item.tipoCbte === 'M'
    ? (parseFloat(impTotal) / 1.21).toFixed(2)
    : impTotal;
  const impIva   = item.tipoCbte === 'A' || item.tipoCbte === 'M'
    ? (parseFloat(impTotal) - parseFloat(impNeto)).toFixed(2)
    : '0.00';

  const fchDesde = fmtFecha(item.fchServDesde || today);
  const fchHasta = fmtFecha(item.fchServHasta || today);
  const fchVto   = fmtFecha(item.fchVtoPago   || today);

  let ivaXml = '';
  if (item.tipoCbte === 'A' || item.tipoCbte === 'M') {
    ivaXml = `
              <ar:Iva>
                <ar:AlicIva>
                  <ar:Id>${alicId}</ar:Id>
                  <ar:BaseImp>${impNeto}</ar:BaseImp>
                  <ar:Importe>${impIva}</ar:Importe>
                </ar:AlicIva>
              </ar:Iva>`;
  }

  return `
          <ar:FECAEDetRequest>
            <ar:Concepto>${item.concepto || 2}</ar:Concepto>
            <ar:DocTipo>${docTipo}</ar:DocTipo>
            <ar:DocNro>${docNro}</ar:DocNro>
            <ar:CbteDesde>${nroDesde}</ar:CbteDesde>
            <ar:CbteHasta>${nroHasta}</ar:CbteHasta>
            <ar:CbteFch>${fmtFecha(today)}</ar:CbteFch>
            <ar:ImpTotal>${impTotal}</ar:ImpTotal>
            <ar:ImpTotConc>0.00</ar:ImpTotConc>
            <ar:ImpNeto>${impNeto}</ar:ImpNeto>
            <ar:ImpOpEx>0.00</ar:ImpOpEx>
            <ar:ImpIVA>${impIva}</ar:ImpIVA>
            <ar:ImpTrib>0.00</ar:ImpTrib>
            <ar:FchServDesde>${fchDesde}</ar:FchServDesde>
            <ar:FchServHasta>${fchHasta}</ar:FchServHasta>
            <ar:FchVtoPago>${fchVto}</ar:FchVtoPago>
            <ar:MonId>PES</ar:MonId>
            <ar:MonCotiz>1</ar:MonCotiz>${ivaXml}
          </ar:FECAEDetRequest>`;
}

/**
 * Solicita CAE para un lote de comprobantes del MISMO tipo/PV
 * items: [{ tipoCbte, importeTotal, alicuotaIva, cuit, concepto, fchServDesde, fchServHasta, fchVtoPago }]
 */
async function solicitarCAELote({ token, sign, cuit }, ptoVta, tipoCbteLetra, items, nroInicial) {
  const tipoCbteNum = TIPOS_CBTE[tipoCbteLetra];
  const today = new Date();
  let detalles = '';
  const nros = [];

  items.forEach((item, i) => {
    const nro = nroInicial + i;
    nros.push(nro);
    detalles += buildDetalle(item, nro, nro, today);
  });

  const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ar="${NS}">
  <soap:Body>
    <ar:FECAESolicitar>
      <ar:Auth>
        <ar:Token>${token}</ar:Token>
        <ar:Sign>${sign}</ar:Sign>
        <ar:Cuit>${cuit}</ar:Cuit>
      </ar:Auth>
      <ar:FeCAEReq>
        <ar:FeCabReq>
          <ar:CantReg>${items.length}</ar:CantReg>
          <ar:PtoVta>${ptoVta}</ar:PtoVta>
          <ar:CbteTipo>${tipoCbteNum}</ar:CbteTipo>
        </ar:FeCabReq>
        <ar:FeDetReq>${detalles}
        </ar:FeDetReq>
      </ar:FeCAEReq>
    </ar:FECAESolicitar>
  </soap:Body>
</soap:Envelope>`;

  const resp = await axios.post(WSFEV1_URL, soap, {
    headers: { 'Content-Type': 'text/xml; charset=utf-8', SOAPAction: `"${NS}FECAESolicitar"` },
    timeout: 60000,
  });

  const parsed   = await xml2js.parseStringPromise(resp.data, { explicitArray: false, tagNameProcessors: [xml2js.processors.stripPrefix] });
  const envelope = parsed['Envelope'] || parsed['soapenv:Envelope'];
  const body     = envelope['Body'] || envelope['soapenv:Body'];
  const result   = (body['FECAESolicitarResponse'] || body['FECAESolicitar'])?.['FECAESolicitarResult'];

  if (!result) throw new Error('Respuesta ARCA vacía o inválida');

  // Procesar resultados
  const detResp = result['FeDetResp']?.['FECAEDetResponse'];
  const dets    = Array.isArray(detResp) ? detResp : (detResp ? [detResp] : []);

  const resultados = dets.map((d, i) => ({
    nroComprobante: parseInt(d['CbteDesde'] || nros[i]),
    cae:            d['CAE'] || null,
    vencimientoCAE: d['CAEFchVto'] || null,
    resultado:      d['Resultado'] || 'E',
    observaciones:  (() => {
      const obs = d['Observaciones']?.['Obs'];
      if (!obs) return [];
      const arr = Array.isArray(obs) ? obs : [obs];
      return arr.map(o => `${o['Code']}: ${o['Msg']}`);
    })(),
    errores: (() => {
      const errs = result['Errors']?.['Err'];
      if (!errs) return [];
      const arr = Array.isArray(errs) ? errs : [errs];
      return arr.map(e => `${e['Code']}: ${e['Msg']}`);
    })(),
  }));

  return { resultados, tipoCbteNum, ptoVta };
}




// ═══════════════════════════════════════════════════
// SERVIDOR EXPRESS
// ═══════════════════════════════════════════════════
const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*', methods: ['GET','POST','OPTIONS'] }));
app.use(express.json({ limit: '2mb' }));

let taCache = null;

async function obtenerTA(certPem, keyPem) {
  const ahora = new Date();
  if (taCache && taCache.expiracion > ahora) return taCache;
  const ta  = await loginWSAA(certPem, keyPem);
  const exp = new Date(ta.expiracion);
  taCache   = { token: ta.token, sign: ta.sign, expiracion: exp };
  return taCache;
}

app.get('/', (req, res) => {
  res.json({ ok: true, servicio: 'Fusion CRM — Proxy ARCA WSFEv1', version: '1.0.0', ts: new Date().toISOString() });
});

app.post('/arcaLogin', async (req, res) => {
  try {
    const { certPem, keyPem } = req.body;
    if (!certPem || !keyPem) throw new Error('Faltan certPem o keyPem');
    taCache = null;
    const ta = await obtenerTA(certPem, keyPem);
    res.json({ ok: true, expiracion: ta.expiracion });
  } catch (err) {
    console.error('[arcaLogin]', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/arcaUltimoNumero', async (req, res) => {
  try {
    const { certPem, keyPem, cuit, ptoVta, tipoCbte } = req.body;
    const ta  = await obtenerTA(certPem, keyPem);
    const nro = await ultimoNumero({ ...ta, cuit }, ptoVta, tipoCbte);
    res.json({ ok: true, nro });
  } catch (err) {
    console.error('[arcaUltimoNumero]', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/arcaFacturar', async (req, res) => {
  try {
    const { certPem, keyPem, cuit, ptoVta, items } = req.body;
    if (!certPem || !keyPem || !cuit || !ptoVta || !items?.length)
      throw new Error('Faltan parámetros: certPem, keyPem, cuit, ptoVta, items');

    const ta   = await obtenerTA(certPem, keyPem);
    const auth = { ...ta, cuit };
    const grupos = {};
    items.forEach((item, idx) => {
      const t = item.tipoCbte || 'B';
      if (!grupos[t]) grupos[t] = [];
      grupos[t].push({ ...item, _origIdx: idx });
    });

    const resultadosGlobales = new Array(items.length).fill(null);
    for (const [tipoCbte, grupoItems] of Object.entries(grupos)) {
      const tipoCbteNum = TIPOS_CBTE[tipoCbte];
      if (!tipoCbteNum) {
        grupoItems.forEach(item => { resultadosGlobales[item._origIdx] = { error: 'Tipo ' + tipoCbte + ' no reconocido', empresa: item.empresa }; });
        continue;
      }
      const ultimoNro  = await ultimoNumero(auth, ptoVta, tipoCbteNum);
      const nroInicial = ultimoNro + 1;
      const resultado  = await solicitarCAELote(auth, ptoVta, tipoCbte, grupoItems, nroInicial);
      resultado.resultados.forEach((r, i) => {
        const origIdx = grupoItems[i]._origIdx;
        resultadosGlobales[origIdx] = { empresa: grupoItems[i].empresa, idCliente: grupoItems[i].idCliente, tipoCbte, ptoVta: parseInt(ptoVta), nroComprobante: r.nroComprobante, cae: r.cae, vencimientoCAE: r.vencimientoCAE, resultado: r.resultado, observaciones: r.observaciones, errores: r.errores, importeTotal: grupoItems[i].importeTotal, fecha: new Date().toISOString() };
      });
    }
    res.json({ ok: true, resultados: resultadosGlobales });
  } catch (err) {
    console.error('[arcaFacturar]', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /padron/:cuit  —  consultar padrón público ARCA ───────────────────
app.get('/padron/:cuit', async (req, res) => {
  try {
    const cuit = req.params.cuit.replace(/\D/g, '');
    if (cuit.length !== 11) throw new Error('CUIT inválido (debe tener 11 dígitos)');
    const resp = await axios.get(`https://soa.afip.gob.ar/sr-padron/v2/persona/${cuit}`, {
      headers: { 'Accept': 'application/json' },
      timeout: 10000,
    });
    const d = resp.data?.data;
    if (!d) throw new Error('CUIT no encontrado en el padrón ARCA');

    // Determinar condición IVA
    const impuestos = d.impuestos || [];
    const tieneIVA  = impuestos.some(i => i.idImpuesto === 30);  // IVA RI
    const tieneMono = impuestos.some(i => i.idImpuesto === 20);  // Monotributo
    let condIva = 'Consumidor Final';
    if (tieneIVA)  condIva = 'Responsable Inscripto';
    else if (tieneMono) condIva = 'Monotributista';

    // Tipo de comprobante sugerido
    let tipoCbte = 'B';
    if (condIva === 'Responsable Inscripto') tipoCbte = 'A';
    else if (condIva === 'Monotributista')   tipoCbte = 'C';

    // Razón social o nombre completo
    const razonSocial = d.razonSocial || [d.apellido, d.nombre].filter(Boolean).join(', ');

    // Domicilio
    const dom = d.domicilioFiscal;
    const domicilio = dom
      ? [dom.direccion, dom.localidad, dom.descripcionProvincia].filter(Boolean).join(', ')
      : '';

    res.json({
      ok: true,
      cuit,
      razonSocial,
      condIva,
      tipoCbte,
      domicilio,
      estadoClave: d.estadoClave,
      raw: { impuestos: impuestos.map(i => i.idImpuesto) },
    });
  } catch (err) {
    const status = err.response?.status === 404 ? 404 : 500;
    res.status(status).json({ ok: false, error: err.message });
  }
});

app.listen(PORT, () => console.log('✅ Fusion CRM ARCA Server en puerto', PORT));
