module.exports = {
  content: [
    "../master_app/index.html",
    "../master_app/**/*.js",
    "./panel/templates/**/*.html"
  ],
  safelist: ["min-h-screen", "bg-slate-950", "text-slate-100"],
  corePlugins: {
    preflight: false
  },
  theme: {
    extend: {}
  },
  plugins: []
};
