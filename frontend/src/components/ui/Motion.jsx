import { motion, useReducedMotion } from "framer-motion";

const defaultVariants = {
  hidden: { opacity: 0, y: 18 },
  show: { opacity: 1, y: 0 },
};

export function FadeIn({ children, className, delay = 0, y = 18, once = false, ...props }) {
  const reduce = useReducedMotion();
  if (reduce) {
    return (
      <div className={className} {...props}>
        {children}
      </div>
    );
  }
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y }}
      {...(once
        ? { whileInView: { opacity: 1, y: 0 }, viewport: { once: true, margin: "-40px" } }
        : { animate: { opacity: 1, y: 0 } })}
      transition={{ duration: 0.55, delay, ease: [0.16, 1, 0.3, 1] }}
      {...props}
    >
      {children}
    </motion.div>
  );
}

export function Stagger({ children, className, delay = 0 }) {
  const reduce = useReducedMotion();
  if (reduce) {
    return <div className={className}>{children}</div>;
  }
  return (
    <motion.div
      className={className}
      initial="hidden"
      whileInView="show"
      viewport={{ once: true, margin: "-60px" }}
      variants={{
        hidden: {},
        show: { transition: { staggerChildren: 0.08, delayChildren: delay } },
      }}
    >
      {children}
    </motion.div>
  );
}

export function StaggerItem({ children, className }) {
  return (
    <motion.div
      className={className}
      variants={{
        hidden: defaultVariants.hidden,
        show: {
          ...defaultVariants.show,
          transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] },
        },
      }}
    >
      {children}
    </motion.div>
  );
}
