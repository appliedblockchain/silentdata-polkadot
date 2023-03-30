import yargs from 'yargs'
import { run } from './lib'

const argv = yargs(process.argv.slice(2))
  .options({
    clientId: { type: 'string', demandOption: true },
    clientSecret: { type: 'string', demandOption: true },
    action: { choices: ['create', 'read'], demandOption: true },
    checkId: { type: 'string' },
    walletAddress: { type: 'string' },
  })
  .check(({ action, checkId, walletAddress }: { action: string; checkId?: string; walletAddress?: string }) => {
    if (action === 'create' && !walletAddress) {
      throw new Error('Missing required argument: walletAddress')
    } else if (action === 'read' && !checkId) {
      throw new Error('Missing required argument: checkId')
    }
    return true
  })
  .parseSync()

run({
  clientId: argv.clientId,
  clientSecret: argv.clientSecret,
  action: argv.action,
  checkId: argv.checkId,
  walletAddress: argv.walletAddress,
}).catch((error: Error) => {
  console.log(`An error occurred: ${error.message}`)
})
