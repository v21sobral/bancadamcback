const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Configuração do banco de dados PostgreSQL (Vercel Postgres)
const sequelize = new Sequelize(
    process.env.POSTGRES_DATABASE || 'verceldb',
    process.env.POSTGRES_USER || 'default',
    process.env.POSTGRES_PASSWORD || '',
    {
        host: process.env.POSTGRES_HOST || 'localhost',
        port: process.env.POSTGRES_PORT || 5432,
        dialect: 'postgres',
        dialectOptions: {
            ssl: process.env.NODE_ENV === 'production' ? {
                require: true,
                rejectUnauthorized: false
            } : false
        },
        logging: false,
        pool: {
            max: 5,
            min: 0,
            acquire: 30000,
            idle: 10000
        }
    }
);

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
}, {
    tableName: 'usuarios',
    timestamps: true
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
    tableName: 'mensagens',
    timestamps: true
});

const app = express();

// CORS configurado
const corsOptions = {
    origin: process.env.FRONTEND_URL || '*',
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

const port = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'segredo_super_secreto';

// Middleware para autenticação JWT
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

// Função para criar usuários fixos
async function criarUsuariosFixos() {
    const usuariosFixos = [
        {
            nome: 'Victor Sobral de Moraes',
            email: 'v.moraes@ba.estudante.senai.br',
            senha: 'q1w2e3r4t5*'
        },
        {
            nome: 'Sara Melo',
            email: 'sara.m.jesus@ba.estudante.senai.br',
            senha: 'saracapricorniana'
        },
        {
            nome: 'Fernanda Dantas Moreira Cruz',
            email: 'fernanda.d.cruz@ba.estudante.senai.br',
            senha: 'fernadagloss'
        }
    ];

    console.log('🔄 Verificando usuários fixos...');
    
    for (const usuarioData of usuariosFixos) {
        try {
            const usuarioExistente = await Usuario.findOne({ 
                where: { email: usuarioData.email } 
            });

            if (!usuarioExistente) {
                const hash = await bcrypt.hash(usuarioData.senha, 10);
                await Usuario.create({
                    nome: usuarioData.nome,
                    email: usuarioData.email,
                    senha: hash
                });
                console.log(`✅ Usuário criado: ${usuarioData.nome}`);
            } else {
                console.log(`ℹ️  Usuário já existe: ${usuarioData.nome}`);
            }
        } catch (error) {
            console.error(`❌ Erro ao criar usuário ${usuarioData.email}:`, error.message);
        }
    }
    
    console.log('✅ Verificação de usuários fixos concluída!\n');
}

// ROTAS

// Rota de teste
app.get('/', (req, res) => {
    res.json({ 
        mensagem: 'API Bancada MequiDonalds funcionando!',
        ambiente: process.env.NODE_ENV || 'development',
        timestamp: new Date().toISOString(),
        database: 'Vercel Postgres'
    });
});

// Listar todos os usuários (apenas para debug)
app.get('/usuarios', async (req, res) => {
    try {
        const usuarios = await Usuario.findAll({
            attributes: ['id', 'nome', 'email', 'createdAt']
        });
        res.json(usuarios);
    } catch (error) {
        console.error('Erro:', error);
        res.status(500).json({ mensagem: 'Erro ao buscar usuários.', erro: error.message });
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
        res.status(201).json({ 
            id: novoUsuario.id, 
            nome: novoUsuario.nome, 
            email: novoUsuario.email 
        });
    } catch (error) {
        res.status(400).json({ 
            mensagem: 'Erro ao cadastrar usuário. E-mail pode já estar cadastrado.' 
        });
    }
});

// Login de usuário
app.post('/auth/login', async (req, res) => {
    try {
        const { email, senha } = req.body;
        
        if (!email || !senha) {
            return res.status(400).json({ mensagem: 'Email e senha são obrigatórios.' });
        }
        
        const usuario = await Usuario.findOne({ where: { email } });
        
        if (!usuario) {
            return res.status(401).json({ mensagem: 'Usuário ou senha inválidos.' });
        }
        
        const senhaValida = await bcrypt.compare(senha, usuario.senha);
        
        if (!senhaValida) {
            return res.status(401).json({ mensagem: 'Usuário ou senha inválidos.' });
        }
        
        const token = jwt.sign(
            { id: usuario.id, nome: usuario.nome, email: usuario.email }, 
            SECRET, 
            { expiresIn: '24h' }
        );
        
        res.json({ 
            token, 
            usuario: { 
                id: usuario.id, 
                nome: usuario.nome, 
                email: usuario.email 
            } 
        });
    } catch (error) {
        console.error('❌ Erro ao fazer login:', error);
        res.status(500).json({ mensagem: 'Erro ao fazer login.' });
    }
});

// Listar todas as mensagens
app.get('/mensagens', async (req, res) => {
    try {
        const mensagens = await Mensagem.findAll({ 
            order: [['id', 'DESC']] 
        });
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
            return res.status(400).json({ 
                mensagem: 'Título, texto e dataHora são obrigatórios.' 
            });
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

// Inicialização do banco e servidor
let dbInitialized = false;

async function initializeDatabase() {
    if (dbInitialized) return;
    
    try {
        console.log('🔄 Conectando ao banco de dados...');
        await sequelize.authenticate();
        console.log('✅ Conexão com banco de dados estabelecida.');
        
        await sequelize.sync();
        console.log('✅ Modelos sincronizados com o banco.');
        
        await criarUsuariosFixos();
        
        dbInitialized = true;
    } catch (error) {
        console.error('❌ Erro ao conectar com o banco:', error);
        throw error;
    }
}

// Para Vercel (serverless)
if (process.env.VERCEL) {
    module.exports = async (req, res) => {
        await initializeDatabase();
        return app(req, res);
    };
} else {
    // Para ambiente local
    initializeDatabase().then(() => {
        app.listen(port, () => {
            console.log(`🚀 API rodando em http://localhost:${port}`);
        });
    }).catch(err => {
        console.error('Erro fatal:', err);
    });
}
