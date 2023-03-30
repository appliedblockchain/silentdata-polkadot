import { silentdata, Silentdata, CheckType, CheckBlockchain } from '@appliedblockchain/silentdata-node'
import { BASE_URL } from './constants'
import { printCertificateData } from './util'

async function create(silentdataClient: Silentdata, walletAddress: string): Promise<void> {
  const check = await silentdataClient.checks.create({
    type: CheckType.instagram,
    data: {
      blockchain: CheckBlockchain.polkadot,
      walletAddress,
    },
  })
  console.log(check.data)
}

async function read(silentdataClient: Silentdata, checkId: string): Promise<void> {
  const check = await silentdataClient.checks.readById({
    type: CheckType.instagram,
    id: checkId,
  })
  printCertificateData(check.data.check)
}

export async function run({
  clientId,
  clientSecret,
  action,
  checkId,
  walletAddress,
}: {
  clientId: string
  clientSecret: string
  action: string
  checkId?: string
  walletAddress?: string
}): Promise<void> {
  const silentdataClient = silentdata({
    clientId,
    clientSecret,
    baseUrl: BASE_URL,
  })

  if (action === 'create') {
    await create(silentdataClient, walletAddress as string)
  } else if (action === 'read') {
    await read(silentdataClient, checkId as string)
  } else {
    throw new Error(`Unhandled "${action}" action`)
  }
}
