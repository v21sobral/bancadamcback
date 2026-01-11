const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Criando conexão com o banco de dados MySQL.
const sequelize = new Sequelize('bancadamc', 'root', '', {
    host: 'localhost',
    dialect: 'mysql'
});

// Modelo para tabela de usuários
const Usuario = sequelize.define('Usuario', {
    nome: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    senha: {
        type: DataTypes.STRING,
        allowNull: false
    }
});

// Modelo para tabela de mensagens
const Mensagem = sequelize.define('Mensagem', {
    titulo: {
        type: DataTypes.STRING,
        allowNull: false
    },
    texto: {
        type: DataTypes.TEXT,
        allowNull: false
    },
    dataHora: {
        type: DataTypes.STRING,
        allowNull: false
    }
}, {
    tableName: 'Mensagens',
    timestamps: true
});

const app = express(); // INICIALIZA O EXPRESS
app.use(cors()); // PERMITE QUE API ACEITE CONEXÃO DO FRONT-END.
app.use(express.json()); // HABILITA O EXPRESS PARA ENTENDER REQUISIÇÕES COM JSON;

const port = process.env.PORT || 3000; // PORTA QUE A APLICAÇÃO VAI RODAR

// Middleware para autenticação JWT
const SECRET = 'segredo_super_secreto'; // Em produção, use variável de ambiente
function autenticarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ mensagem: 'Token não fornecido.' });
    jwt.verify(token, SECRET, (err, usuario) => {
        if (err) return res.status(403).json({ mensagem: 'Token inválido.' });
        req.usuario = usuario;
        next();
    });
}

// ROTA DE TESTE
app.get('/', (req, res) => {
    res.send('API está funcionando!');
});

// ROTA PARA LISTAR TODOS OS USUÁRIOS
app.get('/usuarios', async (req, res) => {
    const usuarios = await Usuario.findAll();
    res.json(usuarios);
});

// ROTA PARA CRIAR UM NOVO USUÁRIO (LEGADO - usar /auth/cadastrar)
app.post('/usuarios', async (req, res) => {
    try {
        const { nome, email } = req.body;
        const novoUsuario = await Usuario.create({ nome, email });
        res.status(201).json(novoUsuario);
    } catch (error) {
        res.status(400).json({ mensagem: "E-mail já cadastrado." });
    }
});

// Cadastro de usuário
app.post('/auth/cadastrar', async (req, res) => {
    try {
        const { nome, email, senha } = req.body;
        if (!nome || !email || !senha) {
            return res.status(400).json({ mensagem: 'Nome, email e senha são obrigatórios.' });
        }
        const hash = await bcrypt.hash(senha, 10);
        const novoUsuario = await Usuario.create({ nome, email, senha: hash });
        res.status(201).json({ id: novoUsuario.id, nome: novoUsuario.nome, email: novoUsuario.email });
    } catch (error) {
        res.status(400).json({ mensagem: 'Erro ao cadastrar usuário. E-mail pode já estar cadastrado.' });
    }
});

// Login de usuário
app.post('/auth/login', async (req, res) => {
    try {
        const { email, senha } = req.body;
        console.log('📧 Email recebido:', email);
        console.log('🔐 Senha recebida:', senha);
        
        const usuario = await Usuario.findOne({ where: { email } });
        if (!usuario) {
            console.log('❌ Usuário não encontrado no banco');
            return res.status(401).json({ mensagem: 'Usuário ou senha inválidos.' });
        }
        
        console.log('✅ Usuário encontrado:', usuario.email);
        console.log('🔐 Senha no banco:', usuario.senha);
        
        // Compatibilidade: aceita senhas hashadas (bcrypt) ou texto plano (legado)
        let senhaValida = false;
        
        // Tenta bcrypt primeiro
        senhaValida = await bcrypt.compare(senha, usuario.senha);
        console.log('🔐 Resultado bcrypt.compare:', senhaValida);
        
        // Se bcrypt falhar, tenta comparação direta (texto plano)
        if (!senhaValida) {
            senhaValida = usuario.senha === senha;
            console.log('🔐 Resultado comparação direta:', senhaValida);
        }
        
        if (!senhaValida) {
            console.log('❌ Senha inválida');
            return res.status(401).json({ mensagem: 'Usuário ou senha inválidos.' });
        }
        
        const token = jwt.sign({ id: usuario.id, nome: usuario.nome, email: usuario.email }, SECRET, { expiresIn: '2h' });
        console.log('✅ Login bem-sucedido');
        res.json({ token, usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email } });
    } catch (error) {
        console.error('❌ Erro ao fazer login:', error);
        res.status(500).json({ mensagem: 'Erro ao fazer login.' });
    }
});

// ROTAS PARA MENSAGENS

// Listar todas as mensagens
app.get('/mensagens', async (req, res) => {
    try {
        const mensagens = await Mensagem.findAll({ order: [['id', 'DESC']] });
        console.log('📨 Mensagens encontradas:', mensagens.length);
        res.json(mensagens);
    } catch (error) {
        console.error('❌ Erro ao buscar mensagens:', error);
        res.status(500).json({ mensagem: 'Erro ao buscar mensagens.' });
    }
});

// Criar uma nova mensagem (apenas autenticado)
app.post('/mensagens', autenticarToken, async (req, res) => {
    try {
        const { titulo, texto, dataHora } = req.body;
        if (!titulo || !texto || !dataHora) {
            return res.status(400).json({ mensagem: 'Título, texto e dataHora são obrigatórios.' });
        }
        const novaMensagem = await Mensagem.create({ titulo, texto, dataHora });
        res.status(201).json(novaMensagem);
    } catch (error) {
        res.status(500).json({ mensagem: 'Erro ao criar mensagem.' });
    }
});

// Editar uma mensagem existente (apenas autenticado)
app.put('/mensagens/:id', autenticarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { titulo, texto } = req.body;
        const mensagem = await Mensagem.findByPk(id);
        if (!mensagem) {
            return res.status(404).json({ mensagem: 'Mensagem não encontrada.' });
        }
        if (!titulo || !texto) {
            return res.status(400).json({ mensagem: 'Título e texto são obrigatórios.' });
        }
        mensagem.titulo = titulo;
        mensagem.texto = texto;
        await mensagem.save();
        res.json(mensagem);
    } catch (error) {
        res.status(500).json({ mensagem: 'Erro ao editar mensagem.' });
    }
});

// Apagar uma mensagem existente (apenas autenticado)
app.delete('/mensagens/:id', autenticarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const mensagem = await Mensagem.findByPk(id);
        if (!mensagem) {
            return res.status(404).json({ mensagem: 'Mensagem não encontrada.' });
        }
        await mensagem.destroy();
        res.json({ mensagem: 'Mensagem apagada com sucesso.' });
    } catch (error) {
        res.status(500).json({ mensagem: 'Erro ao apagar mensagem.' });
    }
});

// SINCRONIZA O MODELO COM O BANCO DE DADOS E INICIA O SERVIDOR
sequelize.sync().then(async () => {
    // Verifica quantas mensagens existem
    const count = await Mensagem.count();
    console.log(`🚀API rodando em http://localhost:${port}`);
    console.log('🚀Conectado ao banco de dados MySQL.');
    console.log(`📊 Total de mensagens no banco: ${count}`);
    app.listen(port);
}).catch(err => {
    console.error('Não foi possível conectar ao banco de dados:');
});