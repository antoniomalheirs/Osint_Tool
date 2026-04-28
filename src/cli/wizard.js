import { select, input, confirm } from '@inquirer/prompts';
import chalk from 'chalk';
import { executeHunt } from '../../index.js'; // Note: we'll have to export executeHunt from index.js or move it
import { showBanner } from './ui.js';

export async function startWizard() {
  console.clear();
  showBanner();
  console.log(chalk.gray(`Bem-vindo ao assistente interativo.\n`));

  try {
    const targetType = await select({
      message: 'O que você deseja investigar?',
      choices: [
        { name: '👤 Username (Apelido)', value: 'username' },
        { name: '📧 E-mail', value: 'email' },
        { name: '🏷️  Nome Completo', value: 'fullname' },
        { name: '❌ Sair', value: 'exit' },
      ],
    });

    if (targetType === 'exit') {
      console.log(chalk.gray('Encerrando sessão...'));
      process.exit(0);
    }

    const target = await input({
      message: `Digite o ${targetType === 'username' ? 'Username' : targetType === 'email' ? 'E-mail' : 'Nome Completo'} do alvo:`,
      validate: (value) => value.trim().length > 0 ? true : 'O alvo não pode estar vazio.',
    });

    const useNSFW = await confirm({
      message: 'Deseja incluir sites NSFW (Adultos) na busca?',
      default: false,
    });

    const exportFormat = await select({
      message: 'Deseja exportar os resultados?',
      choices: [
        { name: 'Nenhum (Apenas Terminal)', value: 'none' },
        { name: 'Relatório HTML Premium', value: 'html' },
        { name: 'Arquivo JSON', value: 'json' },
        { name: 'Arquivo CSV', value: 'csv' },
      ],
      default: 'none'
    });

    const options = {
      nsfw: useNSFW,
      export: exportFormat !== 'none' ? exportFormat : '',
      strictOperational: true, // Padrão corporativo
    };

    console.log(chalk.cyan(`\nIniciando caçada por: ${chalk.bold(target)}...\n`));
    
    // Vamos chamar o executeHunt do index.js. Para isso precisamos garantir que ele é exportado
    // Ou importar a função que roda o Hunt diretamente.
    const { executeHunt } = await import('../../index.js');
    await executeHunt(target, options);

  } catch (error) {
    if (error.name === 'ExitPromptError') {
      console.log(chalk.gray('\nAssistente cancelado pelo usuário.'));
    } else {
      console.error(chalk.red(`Erro no assistente: ${error.message}`));
    }
    process.exit(1);
  }
}
