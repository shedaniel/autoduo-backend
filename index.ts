import {generateKeyPairSync, type KeyObject} from "crypto"
import * as path from "node:path"
import * as fs from "node:fs"
import * as cron from "cron"
import CRYPTO from "node:crypto"

type Account = {
    uid: string
    key: string
    akey: string
    pkey: string
    code: string
    host: string
    json: any
}

function convertPkcs1ToPkcs8(key: string) {
    const privateKey = CRYPTO.createPrivateKey({
        "key": key,
        "format": "pem",
        "type": "pkcs8",
    })
    return privateKey.export({format: "pem", type: "pkcs8"}).toString()
}

function importPrivateKey(pem: string) {
    // fetch the part of the PEM string between header and footer
    const pemHeader = "-----BEGIN PRIVATE KEY-----"
    const pemFooter = "-----END PRIVATE KEY-----"
    const pemContents = pem.substring(
        pemHeader.length,
        pem.length - pemFooter.length - 1,
    )
    const binaryDer = Buffer.from(atob(pemContents), "binary")

    return crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-512"}},
        true,
        ["sign"],
    )
}

async function generateSignature(account: Account, method: string, path: string, time: string, data: object): Promise<string> {
    const message = `${time}
${method}
${account.host.toLowerCase()}
${path}
${new URLSearchParams(data as any).toString()}`
    const cryptoKey = await importPrivateKey(convertPkcs1ToPkcs8(account.key))
    const signed = await crypto.subtle.sign({name: "RSASSA-PKCS1-v1_5"}, cryptoKey, new TextEncoder().encode(message))
    return `Basic ${Buffer.from(`${account.pkey}:${Buffer.from(signed).toString("base64")}`).toString("base64")}`
}

async function getTransactions<T>(account: Account): Promise<T> {
    const time = new Date().toUTCString().replace("GMT", "-0000")
    const path = "/push/v2/device/transactions"
    const data = {akey: account.akey, fips_status: "1", hsm_status: "true", pkpush: "rsa-sha512"}
    const signature = await generateSignature(account, "GET", path, time, data)
    const response = await fetch(`https://${account.host}${path}?${new URLSearchParams(data).toString()}`, {
        headers: {Authorization: signature, "x-duo-date": time, host: account.host},
        method: "GET",
    })
    if (!response.ok) {
        throw new Error(await response.text())
    }
    return await response.json() as T
}

async function reply_transaction(account: Account, transaction_id: string, answer: string) {
    const time = new Date().toUTCString().replace("GMT", "-0000")
    const path = "/push/v2/device/transactions/" + transaction_id
    const data = {
        akey: account.akey, answer: answer, fips_status: "1",
        hsm_status: "true", pkpush: "rsa-sha512",
    }
    const signature = await generateSignature(account, "POST", path, time, data)
    const response = await fetch(`https://${account.host}${path}?${new URLSearchParams(data).toString()}`, {
        headers: {Authorization: signature, "x-duo-date": time, host: account.host, txId: transaction_id},
        method: "POST",
    })
    return await response.json()
}

function parseAccount(json: any): Account {
    return {
        uid: json["uid"],
        key: json["key"],
        akey: json["akey"],
        pkey: json["pkey"],
        code: json["code"],
        host: json["host"],
        json: json,
    }
}

async function newAccount(uid: string, code: string): Promise<Account> {
    const {publicKey, privateKey} = generateKeyPairSync("rsa", {modulusLength: 2048})
    const [parsedCode, host] = parseCode(code)
    let json = await activate(parsedCode, host, publicKey)
    if (json.stat !== "OK") {
        throw new Error(`Failed to activate account: ${json.message}`)
    }
    if (json.response) {
        json = json.response
    }
    json.key = privateKey.export({type: "pkcs1", format: "pem"}).toString()
    json.uid = uid
    json.code = parsedCode
    json.host = host
    return {
        uid: uid,
        key: json.key,
        akey: json.akey,
        pkey: json.pkey,
        code: parsedCode,
        host: host,
        json: json,
    }
}

async function activate(code: string, host: string, key: KeyObject): Promise<any> {
    const params = {
        "customer_protocol": "1", "pubkey": key.export({type: "spki", format: "pem"}).toString().replace(/^\n|\n$/g, ""), "pkpush": "rsa-sha512", "jailbroken": "false", "architecture": "arm64", "region": "US", "app_id": "com.duosecurity.duomobile", "full_disk_encryption": "true",
        "passcode_status": "true", "platform": "Android", "app_version": "3.49.0", "app_build_number": "323001", "version": "11", "manufacturer": "unknown", "language": "en", "model": "AutoDuo", "security_patch_level": "2021-02-01",
    }
    const url = `https://${host}/push/v2/activation/${code}?${new URLSearchParams(params).toString()}`
    console.log(url)
    const response = await fetch(url, {
        method: "POST",
    })
    return await response.json()
}

function parseCode(code: string): [string, string] {
    let [c, h] = code.split("-").map(x => x.replaceAll("<", "").replaceAll(">", ""))
    const missingPadding = h.length % 4
    if (missingPadding) {
        h += "=".repeat(4 - missingPadding)
    }
    return [c, Buffer.from(h, "base64").toString("ascii")]
}

let accounts: Account[] = []
const accountsPath = path.join(__dirname, "accounts.json")
if (fs.existsSync(accountsPath)) {
    const data: any[] = JSON.parse(fs.readFileSync(accountsPath, "utf-8"))
    data.forEach(a => {
        try {
            accounts.push(parseAccount(a))
        } catch (e) {
            console.error(e)
        }
    })
}

new cron.CronJob("*/1 * * * * *", async () => {
    console.log("Checking transactions...")
    for (const account of accounts) {
        try {
            const transactions = (await getTransactions<any>(account))["response"]["transactions"]

            for (const transaction of transactions) {
                console.log(transaction)
                await reply_transaction(account, transaction.urgid, "approve")
            }
        } catch (e) {
            console.error(e)
        }
    }
}).start()

async function handle(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname
    const searchParams = new URL(request.url).searchParams
    if (request.headers.get("x-api-key") !== process.env.API_KEY) {
        return new Response("Unauthorized!", {status: 401})
    }

    console.log(`${request.method} ${path}`)
    // GET /get_accounts/<uid>
    if (request.method === "GET" && path.startsWith("/get_accounts/")) {
        const uid = path.split("/")[2]
        const acc = accounts.filter(a => a.uid === uid)
        return Response.json(acc.map(account => {
            return {
                uid: account.uid,
                code: account.code,
                host: account.host,
                customer_logo: account.json["customer_logo"],
                customer_name: account.json["customer_name"],
            }
        }), {status: 200})
    }

    // POST /add_account query: {uid: string, code: string}
    if (request.method === "POST" && path === "/add_account") {
        const [uid, code] = [searchParams.get("uid"), searchParams.get("code")]
        if (!uid || !code) {
            return Response.json({message: "Invalid input!"}, {status: 400})
        } else if (accounts.some(a => a.uid === uid)) {
            return Response.json({message: "Account limit reached: maximum of 1 accounts tracking!"}, {status: 400})
        }
        console.log(`Adding account for ${uid}: ${code}`)
        try {
            const account = await newAccount(uid, code)
            accounts.push(account)
            fs.writeFileSync(accountsPath, JSON.stringify(accounts.map(a => a.json), null, 2))
            return Response.json(account, {status: 200})
        } catch (e) {
            console.error(e)
            return Response.json({message: e instanceof Error ? e.message : "Error!"}, {status: 400})
        }
    }

    // POST /remove_account query: {uid: string, code: string}
    if (request.method === "POST" && path === "/remove_account") {
        const [uid, code] = [searchParams.get("uid"), searchParams.get("code")]
        if (!uid || !code) {
            return Response.json({message: "Invalid input!"}, {status: 400})
        }
        const index = accounts.findIndex(a => a.uid === uid && a.code === code)
        if (index === -1) {
            return Response.json({message: "Account not found!"}, {status: 400})
        }
        accounts.splice(index, 1)
        fs.writeFileSync(accountsPath, JSON.stringify(accounts.map(a => a.json), null, 2))
        return Response.json({message: "Account removed!"}, {status: 200})
    }

    return Response.json({message: "Not found!"}, {status: 404})
}

Bun.serve({
    hostname: "0.0.0.0",
    port: 4040,
    async fetch(request: Request): Promise<Response> {
        return await handle(request).catch(reason => {
            console.error(reason)
            return new Response("Internal Server Error!", {status: 500})
        })
    },
})

